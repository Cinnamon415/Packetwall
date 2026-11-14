/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda, GPL-3.0-or-later.
 * Accessed from native code by name: do not rename classes, fields or methods.
 */
package io.github.cinnamon415.packetwall.engine.model;

public class PayloadChunk {
    public enum ChunkType { RAW, HTTP, WEBSOCKET }

    public byte[] payload;
    public boolean is_sent;
    public long timestamp;
    public ChunkType type;
    public int stream_id;
    public long file_offset = -1;
    public int file_len;
    public boolean file_printable;

    public PayloadChunk(byte[] _payload, ChunkType _type, boolean _is_sent, long _timestamp, int _stream_id) {
        payload = _payload; type = _type; is_sent = _is_sent; timestamp = _timestamp; stream_id = _stream_id;
    }

    public PayloadChunk(ChunkType _type, boolean _is_sent, long _timestamp, int _stream_id,
                        long _file_offset, int _len, boolean _printable) {
        this(null, _type, _is_sent, _timestamp, _stream_id);
        file_offset = _file_offset; file_len = _len; file_printable = _printable;
    }
}
