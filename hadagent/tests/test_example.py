from podl_chain.block import Block, BlockHeader
#test case 1 simply made a block with the wrong height , and then in the function we check if the validation correctly identifies the height mismatch and returns the appropriate message.
def test_validate_wrong_height():
#creating block with wrong height 
    header = BlockHeader(
        version=1,
        height=5,          
        prev_hash=b"abc",
        data_root=b"",
        model_root=b"",
        proof_root=b"",
        ts=0,
        producer_pk=b"",
        sig=b""
    )
    
    block = Block(header=header, records=[])
    
    #This is the validation method and should check the properties of block 
    valid, msg = block.validate(b"abc", 4)

    assert valid is False
    assert msg == "height mismatch"

from podl_chain.block import Block, BlockHeader

#test case 2 same thing previously but with the wrong prev_hash, and then we check if the validation correctly identifies the prev_hash mismatch and returns the appropriate message.
def test_validate_wrong_prev_hash():
    header = BlockHeader(
        version=1,
        height=4,          
        prev_hash=b"bca", 
        data_root=b"",
        model_root=b"",
        proof_root=b"",
        ts=0,
        producer_pk=b"",
        sig=b""
    )
    block = Block(header=header, records=[])
    
    
    valid, msg2 = block.validate(b"abc", 4)

    assert valid is False
    assert msg2 == "prev_hash mismatch"

from podl_chain.block import Block, BlockHeader
#test case 3 test and verfies the root to avoid data tampering 
def test_validate_root():
    
    #creating block with wrong data root to test if validation can catch it
    header = BlockHeader(
        version=1,
        height=4,
        prev_hash=b"abc",
        data_root=b"wrong_data_root",   # wrong on purpose
        model_root=b"",
        proof_root=b"",
        ts=0,
        producer_pk=b"",
        sig=b""
    )

    block = Block(header=header, records=[])

    valid, msg3 = block.validate(b"abc", 4)

    assert valid is False
    assert msg3 == "data_root mismatch"


from podl_chain.block import Block, BlockHeader


#test case 4 make sure our program can acually link together two blocks 
def test_two_block_linkage():
    # Create first block 
    header1 = BlockHeader(
        version=1,
        height=0,
        prev_hash=b"",
        data_root=b"",
        model_root=b"",
        proof_root=b"",
        ts=0,
        producer_pk=b"",
        sig=b""
    )
    block1 = Block(header=header1, records=[])

    # Get the hash of block1
    prev_hash = block1.block_hash()

    # Create second block that links to block1
    header2 = BlockHeader(
        version=1,
        height=1,
        prev_hash=prev_hash,
        data_root=b"",
        model_root=b"",
        proof_root=b"",
        ts=0,
        producer_pk=b"",
        sig=b""
    )
    block2 = Block(header=header2, records=[])

    valid, msg = block2.validate(prev_hash, 1)

    #checking to ensure linkage is working correctly and does not have any mismatches
    assert msg != "prev_hash mismatch"
    assert msg != "height mismatch"