use super::*;

impl TransportActor {
    #[tracing::instrument(
        level = "trace",
        name = "actor.on_inbound",
        skip_all,
        fields(interface_id = packet.interface_id, raw_len = packet.raw.len()),
    )]
    pub(super) fn on_inbound(&mut self, packet: crate::messages::InboundPacket) {
        self.traffic
            .record_rx(packet.interface_id, packet.raw.len() as u64);

        // Strip the IFAC tag if the interface gates membership on one; packets
        // that fail verification are silently dropped so a misconfigured peer
        // can't leak into a closed access group.
        let raw: bytes::Bytes = if let Some(entry) = self.interfaces.get(&packet.interface_id) {
            if let Some(ref ifac_key) = entry.ifac_key {
                let ifac_size = entry.ifac_size;
                match crate::ifac::ifac_verify(&packet.raw, ifac_key, ifac_size) {
                    Some(stripped) => bytes::Bytes::from(stripped),
                    None => {
                        trace!(
                            interface_id = packet.interface_id,
                            "IFAC verification failed, dropping packet"
                        );
                        return;
                    }
                }
            } else {
                packet.raw.clone()
            }
        } else {
            packet.raw.clone()
        };

        let (mut parsed, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
            Ok((header, offset)) => (header, offset),
            Err(e) => {
                tracing::warn!(
                    interface_id = packet.interface_id,
                    raw_len = raw.len(),
                    first_byte = format!("0x{:02x}", raw.first().copied().unwrap_or(0)),
                    error = %e,
                    "inbound packet dropped: header parse failed"
                );
                return;
            }
        };

        // Dedup via the packet hashlist. A handful of contexts legitimately
        // repeat (keepalives, resource transfer frames, channel traffic) and
        // must bypass the check.
        let pkt_hash = rns_wire::hash::packet_hash(&raw, parsed.flags.header_type);
        self.record_packet_metrics(
            pkt_hash,
            PacketMetrics {
                rssi: packet.rssi,
                snr: packet.snr,
                q: packet.q,
            },
        );
        let skip_hashlist = matches!(
            parsed.context,
            rns_wire::context::PacketContext::Keepalive
                | rns_wire::context::PacketContext::Resource
                | rns_wire::context::PacketContext::ResourceReq
                | rns_wire::context::PacketContext::ResourcePrf
                | rns_wire::context::PacketContext::CacheRequest
                | rns_wire::context::PacketContext::Channel
        );

        // On shared media (e.g. LoRa) we overhear our own forwards and link
        // traffic; if we dedup against that, legitimate copies disappear.
        // Defer the hashlist check for packets owned by the link table or
        // carrying link-proof context.
        let defer_hashlist = self.link_table.contains(&parsed.destination_hash)
            || parsed.context == rns_wire::context::PacketContext::Lrproof;

        if !skip_hashlist && !defer_hashlist && !self.packet_hashlist.insert(pkt_hash) {
            // SINGLE announces are retransmitted to refresh paths, so an
            // exact duplicate is expected and must not be dropped.
            if parsed.flags.packet_type == rns_wire::flags::PacketType::Announce
                && parsed.flags.destination_type == rns_wire::flags::DestinationType::Single
            {
            } else {
                trace!("duplicate packet dropped");
                return;
            }
        }

        parsed.hops = self.adjusted_inbound_hops(parsed.hops, packet.interface_id);

        tracing::debug!(
            pkt_type = ?parsed.flags.packet_type,
            dest = %hex::encode(parsed.destination_hash),
            hops = parsed.hops,
            interface_id = packet.interface_id,
            raw_len = raw.len(),
            "inbound packet received"
        );

        match parsed.flags.packet_type {
            rns_wire::flags::PacketType::Announce => {
                self.process_announce(&raw, &parsed, data_offset, packet.interface_id);
            }
            rns_wire::flags::PacketType::LinkRequest => {
                self.process_link_request(&raw, &parsed, packet.interface_id);
            }
            rns_wire::flags::PacketType::Proof => {
                self.process_proof(&raw, &parsed, packet.interface_id);
            }
            rns_wire::flags::PacketType::Data => {
                self.process_data(&raw, &parsed, packet.interface_id);
            }
        }
    }

    fn process_announce(
        &mut self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        data_offset: usize,
        interface_id: InterfaceId,
    ) {
        let is_from_local_client = self.is_local_client_interface(interface_id);

        if header.hops > PATHFINDER_M {
            debug!(hops = header.hops, "announce exceeded hop limit");
            return;
        }

        if self.local_destinations.contains(&header.destination_hash) {
            debug!("dropping own announce");
            return;
        }

        // Per-interface ingress control. Record the announce and, if the
        // interface is burst-limiting, hold it for later release by the
        // maintenance tick rather than processing now.
        //
        // Bypass the hold when the announce answers an outstanding path
        // request: the announce *is* the resolution, and delaying it there
        // would stall the requester for no gain.
        let answers_path_request = self.path_requests.contains_key(&header.destination_hash)
            || self
                .discovery_path_requests
                .contains_key(&header.destination_hash);
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.ingress.received_announce();
            if !is_from_local_client
                && !answers_path_request
                && entry.ingress.should_ingress_limit()
            {
                entry.ingress.hold_announce(crate::ingress::HeldAnnounce {
                    raw: bytes::Bytes::copy_from_slice(raw),
                    destination_hash: header.destination_hash,
                    hops: header.hops,
                    receiving_interface_id: interface_id,
                });
                debug!(
                    dest = hex::encode(header.destination_hash),
                    interface = interface_id,
                    "announce held by ingress controller (burst active)"
                );
                return;
            }
        }

        let mut rate_blocked = false;

        // Per-interface rate limiting is opt-in and suppresses rebroadcast
        // only; Python still learns the path, updates caches and dispatches
        // handlers for blocked announces. Path responses bypass this gate.
        let has_interface_rate_limit = header.context
            != rns_wire::context::PacketContext::PathResponse
            && self
                .interfaces
                .get(&interface_id)
                .is_some_and(|entry| entry.announce_rate_target.is_some());
        let interface_rate_blocked = if has_interface_rate_limit {
            self.interfaces
                .get(&interface_id)
                .and_then(|entry| {
                    entry.announce_rate_target.map(|target| {
                        self.rate_table.check_interface_rate(
                            header.destination_hash,
                            target,
                            entry.announce_rate_grace.unwrap_or(0),
                            entry.announce_rate_penalty.unwrap_or(0.0),
                        )
                    })
                })
                .unwrap_or(false)
        } else {
            false
        };
        if interface_rate_blocked {
            debug!(
                dest = hex::encode(header.destination_hash),
                interface = interface_id,
                "announce blocked by per-interface rate limit"
            );
            rate_blocked = true;
        } else {
            // Always record non-interface-limited announces for observability.
            // `check_interface_rate` already stores its own timestamp state.
            self.rate_table.record(header.destination_hash);
        }

        let (
            announce_app_data,
            announce_public_key,
            announce_ratchet,
            announce_name_hash,
            announce_identity_hash,
            announce_random_hash,
        ) = {
            if data_offset >= raw.len() {
                tracing::warn!(
                    dest = hex::encode(header.destination_hash),
                    "announce missing payload, dropping"
                );
                return;
            }

            let payload = &raw[data_offset..];
            let has_ratchet = header.flags.context_flag;
            tracing::debug!(
                dest = hex::encode(header.destination_hash),
                payload_len = payload.len(),
                has_ratchet = has_ratchet,
                header_type = ?header.flags.header_type,
                "announce payload received"
            );
            match rns_identity::announce::AnnounceData::unpack(payload, has_ratchet) {
                Ok(announce_data) => {
                    tracing::debug!(
                        dest = hex::encode(header.destination_hash),
                        app_data_len = announce_data.app_data.as_ref().map(|d| d.len()),
                        has_ratchet_key = announce_data.ratchet.is_some(),
                        "announce unpacked"
                    );
                    let known_public_key = self
                        .recent_announces
                        .get(&header.destination_hash)
                        .and_then(|entry| entry.public_key);
                    match announce_data.validate_with_known_key(
                        &header.destination_hash,
                        known_public_key.as_ref(),
                    ) {
                        Ok(validated_identity) => {
                            if self.blackhole_table.is_blackholed(&validated_identity.hash) {
                                trace!(
                                    identity = hex::encode(validated_identity.hash),
                                    dest = hex::encode(header.destination_hash),
                                    "announce from blackholed identity, dropping"
                                );
                                return;
                            }

                            tracing::debug!(
                                dest = hex::encode(header.destination_hash),
                                app_data_present = announce_data.app_data.is_some(),
                                "announce validated"
                            );
                            (
                                announce_data.app_data.clone(),
                                Some(validated_identity.get_public_key()),
                                announce_data.ratchet,
                                announce_data.name_hash,
                                Some(validated_identity.hash),
                                announce_data.random_hash,
                            )
                        }
                        Err(e) => {
                            tracing::warn!(
                                dest = hex::encode(header.destination_hash),
                                payload_len = payload.len(),
                                error = %e,
                                "announce validation failed, dropping"
                            );
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        dest = hex::encode(header.destination_hash),
                        payload_len = payload.len(),
                        has_ratchet = has_ratchet,
                        error = %e,
                        "announce unpack failed, dropping"
                    );
                    return;
                }
            }
        };

        let iface_mode = self
            .interfaces
            .get(&interface_id)
            .map(|e| e.mode)
            .unwrap_or(InterfaceMode::Gateway);

        let announce_emitted = announce_timebase(&announce_random_hash);

        // Cancel our queued rebroadcast when a neighbor already carried it.
        // Same-hop neighbor rebroadcast counts toward the local cap;
        // strict hops+1 forward drops our queued copy outright.
        if self.is_transport_enabled {
            if let Some(existing) = self.announce_table.get(&header.destination_hash) {
                let existing_hops = existing.hops;
                let existing_retries = existing.retries;
                if header.hops > 0 && header.hops - 1 == existing_hops && existing_retries > 0 {
                    let existing_local_rebroadcasts = existing.local_rebroadcasts + 1;
                    if existing_local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                        debug!(
                            dest = hex::encode(header.destination_hash),
                            "announce dedup: local rebroadcast limit reached, removing from table"
                        );
                        self.announce_table.remove(&header.destination_hash);
                    } else if let Some(ae) = self.announce_table.get_mut(&header.destination_hash) {
                        ae.local_rebroadcasts = existing_local_rebroadcasts;
                    }
                }
                if header.hops > 0 && header.hops - 1 == existing_hops + 1 && existing_retries > 0 {
                    let now = now_f64();
                    if let Some(ae) = self.announce_table.get(&header.destination_hash) {
                        if now < ae.retransmit_timeout {
                            debug!(
                                dest = hex::encode(header.destination_hash),
                                "announce dedup: passed on by another node, cancelling rebroadcast"
                            );
                            self.announce_table.remove(&header.destination_hash);
                        }
                    }
                }
            }
        }

        let mut random_blobs = self
            .path_table
            .get(&header.destination_hash)
            .map(|entry| entry.random_blobs.clone())
            .unwrap_or_default();
        let should_add = if let Some(existing) = self.path_table.get(&header.destination_hash) {
            let random_seen = existing.has_random_blob(&announce_random_hash);
            let path_timebase = path_timebase_from_random_blobs(existing.random_blobs.iter());
            if header.hops <= existing.hops {
                !random_seen && announce_emitted > path_timebase
            } else if existing.is_expired() || announce_emitted > path_timebase {
                !random_seen
            } else if announce_emitted == path_timebase {
                self.path_table.get_state(&header.destination_hash)
                    == crate::constants::PathState::Unresponsive
            } else {
                false
            }
        } else {
            true
        };

        if should_add {
            // Announce-table update MUST precede path-table update — the dedup
            // check above compares against our own queued copy. Non-transport
            // nodes never queue (would amplify the announce per hub).
            if !rate_blocked
                && (self.is_transport_enabled || is_from_local_client)
                && header.context != rns_wire::context::PacketContext::PathResponse
                && header.hops < PATHFINDER_M
            {
                let now = now_f64();
                let mut rebroadcast_raw = raw.to_vec();
                if rebroadcast_raw.len() >= 2 {
                    rebroadcast_raw[1] = header.hops;
                }
                let announce_entry = crate::announce::AnnounceEntry {
                    timestamp: now,
                    retransmit_timeout: if is_from_local_client {
                        now
                    } else {
                        now + rand_window()
                    },
                    retries: 0,
                    received_from: header.transport_id.unwrap_or(header.destination_hash),
                    hops: header.hops,
                    packet_raw: rebroadcast_raw,
                    local_rebroadcasts: 0,
                    block_rebroadcast: false,
                    attached_interface: None,
                    source_interface: Some(interface_id),
                };
                self.announce_table
                    .insert(header.destination_hash, announce_entry);
            }

            // For Header2 announces via a transport node, next_hop is the relay's
            // hash from transport_id; for Header1 announces the destination is
            // directly reachable and next_hop stays None.
            let mut entry = crate::path_table::PathEntry::new(
                header.transport_id,
                header.hops,
                interface_id,
                iface_mode,
            );
            if !random_blobs.contains(&announce_random_hash) {
                if random_blobs.len() >= MAX_RANDOM_BLOBS {
                    random_blobs.pop_front();
                }
                random_blobs.push_back(announce_random_hash);
            }
            entry.random_blobs = random_blobs;
            // Store the announce packet hash so a later CacheRequest for this
            // destination can replay the exact announce bytes.
            entry.packet_hash = Some(rns_wire::hash::packet_hash(raw, header.flags.header_type));
            self.path_table.insert(header.destination_hash, entry);
            self.state_dirty = true;
            // Wake any callers waiting on a path for this destination.
            self.fire_path_waiters(&header.destination_hash);

            if let Some(request) = self
                .discovery_path_requests
                .get(&header.destination_hash)
                .copied()
            {
                let response = self.path_response_from_cached_announce(
                    raw,
                    header.destination_hash,
                    header.hops,
                );
                self.send_to_interface(request.requesting_interface, &response);
            }

            debug!(
                dest = hex::encode(header.destination_hash),
                hops = header.hops,
                next_hop = ?header.transport_id.map(hex::encode),
                "path learned from announce"
            );
        } else {
            debug!(
                dest = hex::encode(header.destination_hash),
                hops = header.hops,
                announce_emitted,
                "ignoring replayed or stale announce"
            );
            return;
        }

        // Diagnostics + identity cache. `retained` pins survive re-announce so
        // a fresh announce never silently un-pins an RPC-retained destination.
        // Bounded by `cleanup_known_destinations` (7-day eviction); no count cap.
        let now_ts = now_f64();
        let raw_vec = raw.to_vec();
        let app_data_for_handlers = announce_app_data.clone();
        match self.recent_announces.entry(header.destination_hash) {
            std::collections::hash_map::Entry::Occupied(mut o) => {
                let e = o.get_mut();
                e.hops = header.hops;
                e.app_data = announce_app_data;
                e.timestamp = now_ts;
                e.public_key = announce_public_key;
                e.ratchet = announce_ratchet;
                e.raw_packet = raw_vec;
                e.name_hash = announce_name_hash;
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(RecentAnnounce {
                    dest_hash: header.destination_hash,
                    hops: header.hops,
                    app_data: announce_app_data,
                    timestamp: now_ts,
                    public_key: announce_public_key,
                    ratchet: announce_ratchet,
                    raw_packet: raw_vec,
                    retained: false,
                    name_hash: announce_name_hash,
                });
                self.state_dirty = true;
            }
        }

        if is_from_local_client && header.context == rns_wire::context::PacketContext::PathResponse
        {
            if let Some(waiting_interface) = self
                .pending_local_path_requests
                .remove(&header.destination_hash)
            {
                let response = self.path_response_from_cached_announce(
                    raw,
                    header.destination_hash,
                    header.hops,
                );
                self.send_to_interface(waiting_interface, &response);
            }
        }

        self.send_announce_to_local_clients(
            raw,
            header.destination_hash,
            header.hops,
            Some(interface_id),
            rns_wire::context::PacketContext::None,
        );

        // Aspect-filtered handler dispatch: for handlers with a non-None
        // `aspect_filter`, fire only when
        // `hash_from_name_and_identity(filter, identity_hash) == destination_hash`.
        // Without a validated identity, filtered handlers are skipped.
        if !self.announce_handlers.is_empty() {
            let handler_app_data = app_data_for_handlers;
            let is_path_response = header.context == rns_wire::context::PacketContext::PathResponse;
            let announce_packet_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
            for registration in &self.announce_handlers {
                if is_path_response && !registration.receive_path_responses {
                    continue;
                }
                if let Some(filter) = &registration.aspect_filter {
                    let Some(ref ih) = announce_identity_hash else {
                        continue;
                    };
                    let expected =
                        rns_identity::destination::Destination::hash_from_name_and_identity(
                            filter,
                            Some(ih),
                        );
                    if expected != header.destination_hash {
                        continue;
                    }
                }
                let _ = registration
                    .tx
                    .try_send(crate::messages::AnnounceHandlerEvent {
                        destination_hash: header.destination_hash,
                        identity_hash: announce_identity_hash,
                        announce_packet_hash,
                        is_path_response,
                        hops: header.hops,
                        app_data: handler_app_data.clone(),
                        public_key: announce_public_key,
                        ratchet: announce_ratchet,
                        name_hash: announce_name_hash,
                    });
            }
        }
    }

    /// Well-known PLAIN destination hash for tunnel-synthesis announces.
    fn tunnel_synthesize_dest_hash() -> [u8; 16] {
        rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.tunnel.synthesize",
            None,
        )
    }

    /// Well-known PLAIN destination hash for path-request packets.
    fn path_request_dest_hash() -> [u8; 16] {
        rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.path.request",
            None,
        )
    }

    fn process_data(
        &mut self,
        raw: &bytes::Bytes,
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
    ) {
        let from_local_client = self.is_local_client_interface(interface_id);
        let for_local_client = self
            .path_table
            .get(&header.destination_hash)
            .is_some_and(|path| self.is_local_client_interface(path.interface_id));

        let path_request_dest = Self::path_request_dest_hash();
        let tunnel_synth_dest = Self::tunnel_synthesize_dest_hash();
        let is_control_plain = header.destination_hash == path_request_dest
            || header.destination_hash == tunnel_synth_dest;

        if !is_control_plain
            && header.flags.destination_type == rns_wire::flags::DestinationType::Plain
            && header.flags.transport_type == rns_wire::flags::TransportType::Broadcast
        {
            if from_local_client {
                self.broadcast_on_interfaces(raw, Some(interface_id));
            } else {
                for id in self.local_client_interface_ids_except(Some(interface_id)) {
                    self.send_to_interface(id, raw);
                }
            }
        }

        // Reverse entries only exist to route proofs back through us, so a
        // non-transport node has no reason to keep one unless it is acting for
        // a local shared client.
        if self.is_transport_enabled || from_local_client {
            let pkt_hash = rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
            self.reverse_table
                .insert(pkt_hash, interface_id, header.hops);
        }

        if self.route_link_packet_via_link_table(raw, header, interface_id, "data") {
            return;
        }

        if header.destination_hash == path_request_dest {
            if let Some(payload_start) = self.data_payload_offset(raw, header) {
                let payload = &raw[payload_start..];
                self.handle_inbound_path_request(payload, interface_id);
            }
            return;
        }

        // Tunnel-synthesis: validate the Ed25519 signature, install the
        // tunnel, and replay any cached paths for it. Uses TUNNEL_TIMEOUT
        // (short) rather than DESTINATION_TIMEOUT (long) because the
        // tunnel-layer binding is more volatile than identity lifetime.
        if header.destination_hash == tunnel_synth_dest {
            if let Some(payload_start) = self.data_payload_offset(raw, header) {
                let payload = &raw[payload_start..];
                if let Some(synth_data) = crate::tunnel::TunnelSynthesisData::unpack(payload) {
                    let ed25519_pub_bytes: [u8; 32] = {
                        let mut buf = [0u8; 32];
                        // First 32 bytes of the 64-byte public_key blob are
                        // the Ed25519 signing key; remaining 32 are X25519.
                        buf.copy_from_slice(&synth_data.public_key[..32]);
                        buf
                    };

                    match rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed25519_pub_bytes) {
                        Ok(verify_key) => {
                            let mut signed_data = Vec::with_capacity(112);
                            signed_data.extend_from_slice(&synth_data.public_key);
                            signed_data.extend_from_slice(&synth_data.interface_hash);
                            signed_data.extend_from_slice(&synth_data.random_hash);

                            if verify_key
                                .verify(&signed_data, &synth_data.signature)
                                .is_ok()
                            {
                                let tunnel_id = synth_data.tunnel_id();
                                debug!(
                                    tunnel_id = hex::encode(&tunnel_id[..16]),
                                    interface_id, "tunnel synthesis request validated"
                                );
                                crate::tunnel::handle_tunnel(
                                    &mut self.tunnel_table,
                                    tunnel_id,
                                    interface_id,
                                    TUNNEL_TIMEOUT as f64,
                                );
                                self.state_dirty = true;

                                self.restore_tunnel_paths(&tunnel_id, interface_id);
                            } else {
                                debug!(
                                    interface_id,
                                    "tunnel synthesis signature verification failed"
                                );
                            }
                        }
                        Err(_) => {
                            debug!(interface_id, "tunnel synthesis invalid Ed25519 public key");
                        }
                    }
                } else {
                    trace!(interface_id, "tunnel synthesis data too short or malformed");
                }
            }
            return;
        }

        if header.context == rns_wire::context::PacketContext::PathResponse {
            let iface_mode = self
                .interfaces
                .get(&interface_id)
                .map(|e| e.mode)
                .unwrap_or(InterfaceMode::Gateway);
            let entry = crate::path_table::PathEntry::new(
                Some(header.destination_hash),
                header.hops,
                interface_id,
                iface_mode,
            );
            self.path_table.insert(header.destination_hash, entry);
            self.state_dirty = true;
            self.fire_path_waiters(&header.destination_hash);
            debug!(
                dest = hex::encode(header.destination_hash),
                "path learned from PathResponse"
            );
            return;
        }

        if header.context == rns_wire::context::PacketContext::CacheRequest {
            self.handle_cache_request(raw, header, interface_id);
            return;
        }

        tracing::info!(
            dest = %hex::encode(header.destination_hash),
            is_local = self.local_destinations.contains(&header.destination_hash),
            has_channel = self.destination_channels.contains_key(&header.destination_hash),
            registered_dests = ?self.local_destinations.iter().map(hex::encode).collect::<Vec<_>>(),
            "data packet routing"
        );
        if self.local_destinations.contains(&header.destination_hash) {
            if let Some(tx) = self.destination_channels.get(&header.destination_hash) {
                if let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                    raw: raw.clone(),
                    interface_id,
                }) {
                    self.channel_drops += 1;
                    warn!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                        "failed to deliver InboundPacket to local destination (channel full)");
                }
            }
            return;
        }

        if self.is_transport_enabled || from_local_client || for_local_client {
            if let Some(path) = self.path_table.get(&header.destination_hash) {
                let target_interface = path.interface_id;
                let mut forwarded = raw.to_vec();
                if forwarded.len() >= 2 {
                    forwarded[1] = header.hops;
                }
                self.send_to_interface(target_interface, &forwarded);
                trace!(
                    dest = hex::encode(header.destination_hash),
                    via_interface = target_interface,
                    "data packet forwarded"
                );
            }
        }
    }

    fn process_link_request(
        &mut self,
        raw: &bytes::Bytes,
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
    ) {
        let from_local_client = self.is_local_client_interface(interface_id);
        let for_local_client = self
            .path_table
            .get(&header.destination_hash)
            .is_some_and(|path| self.is_local_client_interface(path.interface_id));

        if self.is_transport_enabled || from_local_client {
            let pkt_hash = rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
            self.reverse_table
                .insert(pkt_hash, interface_id, header.hops);
        }

        if self.local_destinations.contains(&header.destination_hash) {
            if let Some(tx) = self.destination_channels.get(&header.destination_hash) {
                if let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::LinkRequest {
                    raw: raw.clone(),
                    interface_id,
                }) {
                    self.channel_drops += 1;
                    error!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                        "failed to deliver LinkRequest; link establishment will fail");
                }
            }
            return;
        }

        if let Some(path) = (self.is_transport_enabled || from_local_client || for_local_client)
            .then(|| self.path_table.get(&header.destination_hash))
            .flatten()
        {
            let target_interface = path.interface_id;
            let remaining_hops = path.hops;
            let next_hop = path.next_hop;
            let mut forwarded = raw.to_vec();
            if forwarded.len() >= 2 {
                forwarded[1] = header.hops;
            }
            self.send_to_interface(target_interface, &forwarded);

            // Cache the relay so the matching LRPROOF can be routed back to
            // the initiator without a fresh path lookup. Proof timeout scales
            // with remaining hops and adds a serialization allowance for
            // slow outbound interfaces.
            let link_id = rns_wire::hash::link_id_from_raw(raw, header.flags.header_type);
            let now = now_f64();
            let base_timeout = 60.0 * (remaining_hops.max(1) as f64);
            let extra_timeout = if let Some(iface) = self.interfaces.get(&target_interface) {
                let bitrate = iface.bitrate.max(1) as f64;
                (raw.len() as f64 * 8.0) / bitrate
            } else {
                0.0
            };
            let proof_timeout = now + base_timeout + extra_timeout;
            let link_entry = crate::link_table::LinkEntry {
                timestamp: now,
                next_hop,
                interface_id: target_interface,
                remaining_hops,
                destination_hash: header.destination_hash,
                established: false,
                validated: false,
                proof_timeout,
                receiving_interface: interface_id,
                taken_hops: header.hops,
            };
            self.link_table.insert(link_id, link_entry);

            debug!(
                link_id = hex::encode(link_id),
                dest = hex::encode(header.destination_hash),
                receiving = interface_id,
                outbound = target_interface,
                remaining_hops,
                "link table relay entry created"
            );

            trace!(
                dest = hex::encode(header.destination_hash),
                via_interface = target_interface,
                "link request forwarded"
            );
        }
    }

    fn process_proof(
        &mut self,
        raw: &bytes::Bytes,
        header: &rns_wire::header::PacketHeader,
        _interface_id: InterfaceId,
    ) {
        let from_local_client = self.is_local_client_interface(_interface_id);
        let for_local_client_link =
            self.link_table
                .get(&header.destination_hash)
                .is_some_and(|entry| {
                    self.is_local_client_interface(entry.receiving_interface)
                        || self.is_local_client_interface(entry.interface_id)
                });
        let proof_for_local_client = self
            .reverse_table
            .get(&header.destination_hash)
            .is_some_and(|entry| self.is_local_client_interface(entry.receiving_interface));

        if let Some(receipt) = self.receipt_table.get_mut(&header.destination_hash) {
            let rtt = receipt
                .get_rtt()
                .or_else(|| Some(receipt.sent_at.elapsed()));
            receipt.deliver();

            if let Some(msg_id) = self.receipt_msg_ids.remove(&header.destination_hash) {
                debug!(
                    msg_id = %msg_id,
                    trunc = hex::encode(header.destination_hash),
                    "delivery proof received for outbound message"
                );
                // Broadcast the DeliveryProof to every destination channel —
                // we don't know which local identity originated the outbound
                // message, so LXMF filters by msg_id on its side.
                for (dest_hash, tx) in &self.destination_channels {
                    if let Err(e) =
                        tx.try_send(crate::link_messages::DestinationEvent::DeliveryProof {
                            msg_id: msg_id.clone(),
                            rtt,
                        })
                    {
                        self.channel_drops += 1;
                        error!(dest = hex::encode(dest_hash), msg_id = %msg_id, drops = self.channel_drops, err = %e,
                            "failed to deliver DeliveryProof; sender will not receive confirmation");
                    }
                }
            }
            self.receipt_table.remove(&header.destination_hash);
            return;
        }

        // Link-request proofs route back via the link_table to the interface
        // the original request arrived on.
        //
        // Proofs start at hops=0 at the destination. We normalise inbound
        // hops before dispatch, matching Python Transport's increment-on-
        // receive rule, so the proof must equal the remaining hops recorded
        // when the request was forwarded.
        if header.context == rns_wire::context::PacketContext::Lrproof {
            if self.is_transport_enabled || from_local_client || for_local_client_link {
                if let Some(link_entry) = self.link_table.get(&header.destination_hash) {
                    let expected_hops = link_entry.remaining_hops;
                    let outbound_interface = link_entry.interface_id;
                    let target_interface = link_entry.receiving_interface;

                    // Require that the proof arrived on the same interface we
                    // forwarded the request to; a mismatch is either a routing
                    // change or a spoof and must not be relayed.
                    let hops_match = header.hops == expected_hops;
                    if hops_match && _interface_id == outbound_interface {
                        let mut forwarded = raw.to_vec();
                        if forwarded.len() >= 2 {
                            forwarded[1] = header.hops;
                        }
                        if let Some(entry) = self.link_table.get_mut(&header.destination_hash) {
                            entry.validated = true;
                        }
                        self.send_to_interface(target_interface, &forwarded);
                        debug!(
                            link_id = hex::encode(header.destination_hash),
                            via_interface = target_interface,
                            hops = header.hops,
                            "link proof (LRPROOF) routed via link table"
                        );
                        return;
                    } else if !hops_match {
                        warn!(
                            link_id = hex::encode(header.destination_hash),
                            expected_hops,
                            actual_hops = header.hops,
                            "link proof hop mismatch, not transporting"
                        );
                    } else {
                        warn!(
                            link_id = hex::encode(header.destination_hash),
                            expected_interface = outbound_interface,
                            actual_interface = _interface_id,
                            "link proof received on wrong interface, not transporting"
                        );
                    }
                }
            }

            // Fall through to local-pending-link delivery when link_table
            // didn't claim the proof.
            if let Some(tx) = self.destination_channels.get(&header.destination_hash) {
                if let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                    raw: raw.clone(),
                    interface_id: _interface_id,
                }) {
                    self.channel_drops += 1;
                    warn!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                        "failed to deliver LRPROOF to local pending link (channel full)");
                }
            }
            return;
        }

        if self.route_link_packet_via_link_table(raw, header, _interface_id, "proof") {
            return;
        }

        // Data-packet proofs route back via the reverse_table. When the
        // entry records the outbound interface we forwarded on, enforce the
        // match — a proof on the wrong interface means a routing change or
        // a spoof. Older entries without that field route unconditionally.
        if self.is_transport_enabled || from_local_client || proof_for_local_client {
            if let Some(reverse_entry) = self.reverse_table.remove(&header.destination_hash) {
                if let Some(expected_outbound) = reverse_entry.outbound_interface {
                    if _interface_id != expected_outbound {
                        debug!(
                            dest = hex::encode(header.destination_hash),
                            expected = expected_outbound,
                            actual = _interface_id,
                            "proof arrived on wrong interface, not routing via reverse table"
                        );
                    } else {
                        let target_interface = reverse_entry.receiving_interface;
                        let mut forwarded = raw.to_vec();
                        if forwarded.len() >= 2 {
                            forwarded[1] = header.hops;
                        }
                        self.send_to_interface(target_interface, &forwarded);
                        trace!(
                            dest = hex::encode(header.destination_hash),
                            via_interface = target_interface,
                            "proof routed via reverse table"
                        );
                        return;
                    }
                } else {
                    let target_interface = reverse_entry.receiving_interface;
                    let mut forwarded = raw.to_vec();
                    if forwarded.len() >= 2 {
                        forwarded[1] = header.hops;
                    }
                    self.send_to_interface(target_interface, &forwarded);
                    trace!(
                        dest = hex::encode(header.destination_hash),
                        via_interface = target_interface,
                        "proof routed via reverse table"
                    );
                    return;
                }
            }
        }

        if let Some(tx) = self.destination_channels.get(&header.destination_hash) {
            if let Err(e) = tx.try_send(crate::link_messages::DestinationEvent::InboundPacket {
                raw: raw.clone(),
                interface_id: _interface_id,
            }) {
                self.channel_drops += 1;
                error!(dest = hex::encode(header.destination_hash), drops = self.channel_drops, err = %e,
                    "failed to deliver link proof to local link");
            }
        }
    }

    fn route_link_packet_via_link_table(
        &mut self,
        raw: &[u8],
        header: &rns_wire::header::PacketHeader,
        interface_id: InterfaceId,
        packet_kind: &'static str,
    ) -> bool {
        if header.flags.destination_type != rns_wire::flags::DestinationType::Link
            || self.local_destinations.contains(&header.destination_hash)
        {
            return false;
        }

        let Some(entry) = self.link_table.get(&header.destination_hash).cloned() else {
            return false;
        };

        let shared_client_path = self.is_local_client_interface(interface_id)
            || self.is_local_client_interface(entry.receiving_interface)
            || self.is_local_client_interface(entry.interface_id);
        if !self.is_transport_enabled && !shared_client_path {
            return false;
        }

        let target_interface = if interface_id == entry.receiving_interface {
            entry.interface_id
        } else if interface_id == entry.interface_id {
            entry.receiving_interface
        } else {
            warn!(
                link_id = hex::encode(header.destination_hash),
                interface_id,
                receiving_interface = entry.receiving_interface,
                outbound_interface = entry.interface_id,
                "link packet arrived on interface outside link table path, not transporting"
            );
            return false;
        };

        let mut forwarded = raw.to_vec();
        if forwarded.len() >= 2 {
            forwarded[1] = header.hops;
        }
        if let Some(entry) = self.link_table.get_mut(&header.destination_hash) {
            entry.timestamp = now_f64();
        }
        self.send_to_interface(target_interface, &forwarded);
        trace!(
            link_id = hex::encode(header.destination_hash),
            via_interface = target_interface,
            hops = header.hops,
            packet_kind,
            "link packet routed via link table"
        );
        true
    }
}
