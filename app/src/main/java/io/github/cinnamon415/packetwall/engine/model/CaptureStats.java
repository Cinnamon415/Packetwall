/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda, GPL-3.0-or-later.
 * Accessed from native code by name: do not rename classes, fields or methods.
 */
package io.github.cinnamon415.packetwall.engine.model;

public class CaptureStats {
    public String alloc_summary;
    public long bytes_sent, bytes_rcvd, ipv6_bytes_sent, ipv6_bytes_rcvd, pcap_dump_size;
    public int pkts_sent, pkts_rcvd, pkts_dropped, num_dropped_conns, num_open_sockets, max_fd;
    public int active_conns, tot_conns, num_dns_queries;

    public void setData(String _alloc_summary, long _bytes_sent, long _bytes_rcvd,
                        long _ipv6_bytes_sent, long _ipv6_bytes_rcvd, long _pcap_dump_size,
                        int _pkts_sent, int _pkts_rcvd, int _pkts_dropped, int _num_dropped_conns,
                        int _num_open_sockets, int _max_fd, int _active_conns, int _tot_conns,
                        int _num_dns_queries) {
        alloc_summary = _alloc_summary; bytes_sent = _bytes_sent; bytes_rcvd = _bytes_rcvd;
        ipv6_bytes_sent = _ipv6_bytes_sent; ipv6_bytes_rcvd = _ipv6_bytes_rcvd; pcap_dump_size = _pcap_dump_size;
        pkts_sent = _pkts_sent; pkts_rcvd = _pkts_rcvd; pkts_dropped = _pkts_dropped;
        num_dropped_conns = _num_dropped_conns; num_open_sockets = _num_open_sockets; max_fd = _max_fd;
        active_conns = _active_conns; tot_conns = _tot_conns; num_dns_queries = _num_dns_queries;
    }
}
