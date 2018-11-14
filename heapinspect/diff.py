def heapdiff(old, new):
    '''Heapdiff for HeapRecord.

    Note:
        Based on the start address of chunks. Currently
        support diff of heap_chunks
    Args:
        old (HeapRecord): Old record.
        new (HeapRecord): New record.
    Returns:
        list: A list of changes.
    Examples:
        >>> hi = HeapInspector(1234)
        >>> record1 = hi.record
        >>> sleep(5)
        >>> record2 = hi.record
        >>> heapdiff(record1, record2)
        {
            'heap_chunks': [
                (chunk1, {'type': 'data', 'info': '12345678'}),
                (chunk2, {'type': 'size', 'info': 0x21}),
                (chunk3, {'type': 'new', 'info': None},
                (chunk4, {'type': 'prev_size', 'info': 0}),
                (chunk5, {'type': 'merge', 'info': None}),
                (chunk8, {'type': 'head', 'info':[0, 0x21]})
                ],
            'fastbins': [
                (chunk6, {'type': 'add', 'info': None),
                (chunk7, {'type': 'remove', 'info': None),
            ],
            'smallbins': [],
            'largebins': [],
            'unsortedbins': []
        }
    '''
    result = {}
    # heap_chunks
    heap_chunks = []
    old_heap_chunks = old.heap_chunks
    new_heap_chunks = new.heap_chunks
    idx_old, idx_new = 0, 0
    while idx_old < len(old_heap_chunks) and \
        idx_new < len(new_heap_chunks):
        old_chunk = old_heap_chunks[idx_old]
        new_chunk = new_heap_chunks[idx_new]
        # addr check
        if old_chunk._addr < new_chunk._addr:
            heap_chunks.append((old_chunk, {'type': 'merge', 'info': None}))
            idx_old += 1
            continue
        elif old_chunk._addr > new_chunk._addr:
            heap_chunks.append((new_chunk, {'type': 'new', 'info': None}))
            idx_new += 1
            continue
        # now check prev_size, size, data
        if old_chunk.size != new_chunk.size and \
            old_chunk.prev_size != new_chunk.prev_size:
            heap_chunks.append((new_chunk, {
                'type': 'head', 
                'info': [old_chunk.prev_size, old_chunk.size]
                }))
        elif old_chunk.size != new_chunk.size:
            heap_chunks.append((new_chunk, {
                'type': 'size', 
                'info': old_chunk.size
                }))
        elif old_chunk.prev_size != new_chunk.prev_size:
            heap_chunks.append((new_chunk, {
                'type': 'prev_size', 
                'info': old_chunk.prev_size
                }))
        idx_new += 1
        idx_old += 1
    if idx_old < len(old_heap_chunks):
        for chunk in old_heap_chunks[idx_old:]:
            heap_chunks.append((chunk, {'type': 'merge', 'info': 'top'}))
    elif idx_new < len(new_heap_chunks):
        for chunk in new_heap_chunks[idx_new:]:
            heap_chunks.append((chunk, {'type': 'new', 'info': None}))
    result['heap_chunks'] = heap_chunks
    def chunksdiff(old, new):
        '''Sub-function of heapdiff. Used for fastbins/bins. Not implemented.

        Note:
            Only detect add and remove for now. Ignore the position
            change in the linked list.
        Args:
            old (list): Old chunks to diff.
            new (list): New chunks to diff.
        Return:
            list: results.
        Examples:
            >>> chunks1 = hi.fastbins[0]
            >>> chunks2 = hi2.fastbins[0]
            >>> chunksdiff(chunks1, chunks2)
            [
                (chunk6, {'type': 'add', 'info': None),
                (chunk7, {'type': 'remove', 'info': None),
            ]
        '''
        result = []
        idx_new, idx_old = 0, 0
        while idx_old < len(old) and idx_new < len(new):
            pass
    result['fastbins'] = []
    result['smallbins'] = []
    result['largebins'] = []
    result['unsortedbins'] = []
    return result
