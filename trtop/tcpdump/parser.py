__author__ = 'Thomas Kountis'


TIMESTAMP_IDX = 0
SRC_IDX = 2
DST_IDX = 4
FLAGS_IDX = 6

MIN_LINE_PARTS_LENGTH = 9


def is_valid_line(line):
    parts = line.split(" ")
    return len(parts) >= MIN_LINE_PARTS_LENGTH and parts[1] == "IP" and parts[5] == "Flags"


def _extract_sequence(line):
    index_of_seq = line.find(' seq ')
    seq = line[index_of_seq + 5: line.index(',', index_of_seq)] if index_of_seq > 0 else "0"
    seq = seq.split(":")[1] if seq.find(":") > 0 else seq
    return int(seq)


def _extract_ts_val(line):
    index_of_ts = line.find('TS val') + 7
    return line[index_of_ts: line.index(' ', index_of_ts)]


def _extract_length(line):
    index_of_len = line.find('length') + 7
    index_of_len_end = line.find(':', index_of_len)
    index_of_len_end = index_of_len_end if index_of_len_end > 0 else line.find('', index_of_len) + 1
    return int(line[index_of_len:index_of_len_end])


def _extract_ack(line):
    index_of_ack = line.find(' ack ')
    return int(line[index_of_ack + 5: line.index(',', index_of_ack)]) if index_of_ack > 0 else 0


def build_packet(line):
    parts = line.split(" ")

    from packet import UnifiedPacket
    packet = UnifiedPacket()
    packet.src = parts[SRC_IDX].rpartition(".")[0]
    packet.src_port = int(parts[SRC_IDX].rpartition(".")[2])
    packet.dst = parts[DST_IDX].rpartition(".")[0]
    packet.dst_port = int(parts[DST_IDX].rpartition(".")[2][:-1])
    packet.flags = parts[FLAGS_IDX].replace("[", "").replace("]", "").replace(",", "")
    packet.timestamp = parts[TIMESTAMP_IDX]
    packet.ack = _extract_ack(line)
    packet.sequence = _extract_sequence(line)
    packet.length = _extract_length(line)
    return packet

