def heapchunkscheck(chunks, top):
    '''Check heap chunks.

    Args:
        chunks (list): List of chunks.
        top (int): Top address of heap.
    Returns:
        list: A list of result.
    Examples:
        >>> chunks = hi.heap_chunks
        >>> heapchunkscheck(chunks, hi.main_arena.top)
        [
            [],
            ['size'],
            ['size', 'prev_size'],
            [],
            ['prev_size']
        ]
    '''
    result = []
    for idx, chunk in enumerate(chunks):
        single = []
        # check prev_size and size & 1
        if chunk.size & 1 == 0:
            if idx == 0:
                single.append('size')
            else:
                if chunks[idx-1].size & 0b111 != prev_size:
                    single.append('prev_size')
        if chunk._addr + chunk.size & 0b111 > top:
            single.append('size')
        result.append(single)
    return result

def fastbinscheck(size, chunks, heap_range):
    '''Check fastbins.

    Note:
        Can also be used for tcache.
    Args:
        size (int): Size of fastbins.
        chunks (list): List of chunks.
        heap_range (tuple): Start and end address of heap.
    Returns:
        list: A list of result.
    Examples:
        >>> indexed_chunks = hi.fastbins
        >>> chunks = indexed_chunks[0]
        >>> fastbinscheck(0x20, chunks, hi.ranges['heap'])
        [
            [],
            ['size'],
            ['size', 'fd'],
            [],
            ['fd'],
            ['addr']
        ]
    '''
    result = []
    for chunk in chunks:
        single = []
        # size check
        if chunk.size ~& 0b111 != size:
            single.append('size')
        # fd check
        if fd not in heap_range:
            single.append('fd')
        # addr check
        if chunk._addr not in heap_range:
            single.append('addr')
        result.append(single)
    return result


def binscheck(chunks, heap_range, addr, size=None):
    '''Check bins.

    Note:
        May be only useful for unsortedbins.
    Args:
        chunks (list): List of chunks.
        heap_range (tuple): Start and end address of heap.
        addr (int): Addr of the chunk in arena.
        size (int or tuple, optional): Size check. Disabled by default.
    Returns:
        list: A list of result.
    Examples:
        >>> chunks = hi.unsortedbins
        >>> binscheck(chunks, hi.ranges['heap'])
        [
            [],
            ['size'],
            ['size', 'fd'],
            [],
            ['fd', 'bk'],
            ['addr']
        ]
    '''
    result = []
    for idx, chunk in enumerate(chunks):
        single = []
        if idx == 0:
            prev_addr = addr
        else:
            prev_addr = chunks[idx-1]._addr
        if size:
            if type(size) == tuple or type(size) == list:
                if size[0] <= chunk.size ~& 0b111 < size[1]:
                    pass
                else:
                    single.append(size)
            elif type(size) == int:
                if chunk.size ~& 0b111 != size:
                    single.append(size)
        if chunk._addr not in heap_range:
            single.append('addr')
        if chunk.fd != prev_addr:
            single.append('fd')
        if idx == len(chunks) and chunk.bk != addr:
            single.append('bk')
        result.append(single)
    return result
