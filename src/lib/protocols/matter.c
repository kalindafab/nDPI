/*
 * matter.c
 *
 * Copyright (C) 2025 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "ndpi_protocol_ids.h"
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MATTER
#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_matter(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Matter\n");

  /* Matter typically uses UDP ports 5540 (operational), 5542 (commissioning) */
  u_int16_t matter_port1 = htons(5540);
  u_int16_t matter_port2 = htons(5542);

  if(packet->udp) {
    if((packet->udp->dest == matter_port1) || (packet->udp->source == matter_port1) ||
       (packet->udp->dest == matter_port2) || (packet->udp->source == matter_port2)) {

      /* Matter messages usually have at least a 16-byte header (secure session framing) */
      if(packet->payload_packet_len >= 16) {
        uint8_t flags = packet->payload[0];
        uint8_t version = (flags >> 4) & 0x0F;
        uint8_t session_type = flags & 0x0F;

        if(version <= 4 && session_type <= 4) {
          uint16_t session_id = ntohs(*(uint16_t*)&packet->payload[1]);
          if(session_id != 0) {
            NDPI_LOG_INFO(ndpi_struct, "Matter detected (ver=%u, session=%u, id=%u)\n",
                          version, session_type, session_id);
            ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MATTER,
                                       NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
            return;
          }
        }
      }
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_matter_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  register_dissector("Matter", ndpi_struct,
                     ndpi_search_matter,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD, /* MATTER is only over IPv6 */
                     1, NDPI_PROTOCOL_MATTER);
}
