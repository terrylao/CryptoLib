Unit ClpPKCS1Encoding;

interface
uses clpIAsymmetricBlockCipher,  ClpSecureRandom, ClpAsymmetricKeyParameter,
  ClpISecureRandom,Sysutils,ClpICipherParameters;
  type
{*
 * this does your basic PKCS 1 v1.5 padding - whether or not you should be using this
 * depends on your application - see PKCS1 Version 2 for details.
 }
  TPKCS1Encoding = class//(IAsymmetricBlockCipher)
    const HEADER_LENGTH :integer= 10;
          NOT_STRICT_LENGTH_ENABLED_PROPERTY = 'CodaMina.pkcs1.not_strict';

    {*
     * some providers fail to include the leading zero in PKCS1 encoded blocks. If you need to
     * work with one of these set the system property org.bouncycastle.pkcs1.not_strict to true.
     * <p>
     * The system property is checked during construction of the encoding object, it is set to
     * false by default.
     * </p>
     }
    
      private
        random:ISecureRandom;
        engine:IAsymmetricBlockCipher;
        forEncryption,forPrivateKey,useStrictLength:boolean;
        pLen :integer;
        fallback,blockBuffer :TBytes;
        function checkPkcs1Encoding(encoded:TBytes; lpLen:integer):integer;
        function decodeBlockOrRandom(inbuf:TBytes; inOff, inLen:integer):TBytes;
        function decodeBlock(inbuf:TBytes; inOff, inLen:integer):TBytes;
        function findStart(ltype:byte; block:Tbytes):integer;
      public
        constructor create(cipher:IAsymmetricBlockCipher);
        constructor create( cipher:IAsymmetricBlockCipher; lpLen:integer);
        constructor create(cipher:IAsymmetricBlockCipher;lfallback:Tbytes);
        function  getUnderlyingCipher():IAsymmetricBlockCipher;
        procedure init(lforEncryption:boolean;param:ICipherParameters);
        function getInputBlockSize():integer;
        function getOutputBlockSize():integer;
        function processBlock(inbuf:TBytes;inOff,inLen:integer):TBytes;
        function encodeBlock(inbuf:TBytes;inOff,inLen:integer):TBytes;
  end;
implementation
    {*
     * Basic constructor.
     *
     * @param cipher
     }
    constructor TPKCS1Encoding.create(cipher:IAsymmetricBlockCipher);
    begin
        engine := cipher;
        useStrictLength := false;
        pLen := -1;
    end;

    {*
     * Constructor for decryption with a fixed plaintext length.
     *
     * @param cipher The cipher to use for cryptographic operation.
     * @param pLen   Length of the expected plaintext.
     }
    constructor TPKCS1Encoding.create( cipher:IAsymmetricBlockCipher; lpLen:integer);
    begin
        engine := cipher;
        useStrictLength := false;
        pLen := lpLen;
    end;

    {*
     * Constructor for decryption with a fixed plaintext length and a fallback
     * value that is returned, if the padding is incorrect.
     *
     * @param cipher   The cipher to use for cryptographic operation.
     * @param fallback The fallback value, we don't do an arraycopy here.
     }
    constructor TPKCS1Encoding.create(cipher:IAsymmetricBlockCipher;lfallback:Tbytes);
    begin
      engine := cipher;
      useStrictLength := false;
      fallback := lfallback;
      pLen := length(lfallback);
    end;

    function  TPKCS1Encoding.getUnderlyingCipher():IAsymmetricBlockCipher;
    begin
        result := engine;
    end;

    procedure TPKCS1Encoding.init(lforEncryption:boolean;param:ICipherParameters);
    var
      kParam:TAsymmetricKeyParameter;
    begin

        kParam := TAsymmetricKeyParameter(param);
        if (not kParam.isPrivate) and (lforEncryption) then
        begin
            random := TSecureRandom.Create();
        end;

        engine.init(lforEncryption, param);

        forPrivateKey := kParam.isPrivate;
        forEncryption := lforEncryption;
        setlength(blockBuffer,engine.getOutputBlockSize());

        if (pLen > 0) and (fallback = nil) and (random = nil) then
        begin
           Raise exception.create('encoder requires random');
        end;
    end;

    function TPKCS1Encoding.getInputBlockSize():integer;
    var
      baseBlockSize:integer;
    begin
        baseBlockSize := engine.getInputBlockSize();

        if (forEncryption) then
        begin
            result := baseBlockSize - HEADER_LENGTH;
        end
        else
        begin
            result := baseBlockSize;
        end;
    end;

    function TPKCS1Encoding.getOutputBlockSize():integer;
    var
      baseBlockSize:integer;
    begin
        baseBlockSize := engine.getOutputBlockSize();

        if (forEncryption) then
        begin
            result := baseBlockSize;
        end
        else
        begin
            result := baseBlockSize - HEADER_LENGTH;
        end;
    end;

    function TPKCS1Encoding.processBlock(inbuf:TBytes;inOff,inLen:integer):TBytes;
    begin
        if (forEncryption) then
        begin
            result := encodeBlock(inbuf, inOff, inLen);
        end
        else
        begin
            result := decodeBlock(inbuf, inOff, inLen);
        end;
    end;

    function TPKCS1Encoding.encodeBlock(inbuf:TBytes;inOff,inLen:integer):TBytes;
    var
      block:TBytes;
      i:integer;
    begin
        if (inLen > getInputBlockSize()) then
        begin
            Raise exception.create('input data too large');
        end;

        setlength(block,engine.getInputBlockSize());

        if (forPrivateKey) then
        begin
            block[0] := $01;                        // type code 1

            for i := 1 to  length(block) - inLen - 1-1 do
            begin
                block[i] := $FF;
            end;
        end
        else
        begin
            random.nextBytes(block);                // random fill

            block[0] := $02;                        // type code 2

            //
            // a zero byte marks the end of the padding, so all
            // the pad bytes must be non-zero.
            //
            for i := 1 to length(block) - inLen - 1 -1 do
            begin
                while (block[i] = 0) do
                begin
                    block[i] := byte(random.NextInt32());
                end;
            end;
        end;

        block[length(block) - inLen - 1] := $00;       // mark the end of the padding
        move(inbuf[inOff], block[length(block) - inLen], inLen);
        result := engine.processBlock(block, 0, length(block));
    end;

    {*
     * Checks if the argument is a correctly PKCS#1.5 encoded Plaintext
     * for encryption.
     *
     * @param encoded The Plaintext.
     * @param pLen    Expected length of the plaintext.
     * @return Either 0, if the encoding is correct, or -1, if it is incorrect.
     }
    function TPKCS1Encoding.checkPkcs1Encoding(encoded:TBytes; lpLen:integer):integer;
    var
      correct,i,tmp:integer;
    begin
        correct := 0;
        {
		 * Check if the first two bytes are 0 2
		 }
        correct := correct or (encoded[0] xor 2);

		{
		 * Now the padding check, check for no 0 byte in the padding
		 }
        lplen := length(encoded) - (
            lpLen { Length of the PMS }
                + 1 { Final 0-byte before PMS }
        );

        for i := 1 to lplen -1 do
        begin
            tmp := encoded[i];
            tmp := tmp or tmp shr 1;
            tmp := tmp or tmp shr 2;
            tmp := tmp or tmp shr 4;
            correct := correct or (tmp and 1) - 1;
        end;

		{
		 * Make sure the padding ends with a 0 byte.
		 }
        correct := correct or encoded[length(encoded) - (lpLen + 1)];

		{
		 * Return 0 or 1, depending on the result.
		 }
        correct := correct or correct shr 1;
        correct := correct or correct shr 2;
        correct := correct or correct shr 4;
        result := not ((correct and 1) - 1);
    end;


    {*
     * Decode PKCS#1.5 encoding, and return a random value if the padding is not correct.
     *
     * @param in    The encrypted block.
     * @param inOff Offset in the encrypted block.
     * @param inLen Length of the encrypted block.
     *              //@param pLen Length of the desired output.
     * @return The plaintext without padding, or a random value if the padding was incorrect.
     * @throws InvalidCipherTextException
     }
    function TPKCS1Encoding.decodeBlockOrRandom(inbuf:TBytes; inOff, inLen:integer):TBytes;
    var
      block,lrandom,data:TBytes;
      correct,i:integer;
    begin
        if (not forPrivateKey) then
        begin
            Raise exception.create('sorry, this method is only for decryption, not for signing');
        end;

        block := engine.processBlock(inbuf, inOff, inLen);
        if (fallback = nil) then
        begin
            setlength(lrandom,pLen);
            random.NextBytes(lrandom);
        end
        else
        begin
            lrandom := fallback;
        end;
        if (useStrictLength and (length(block) <> engine.getOutputBlockSize())) then
          data :=blockBuffer 
        else
          data :=block;

		{
		 * Check the padding.
		 }
        correct := checkPkcs1Encoding(data, pLen);
		
		{
		 * Now, to a constant time constant memory copy of the decrypted value
		 * or the random value, depending on the validity of the padding.
		 }
        setlength(result,pLen);
        for i := 0 to pLen -1 do
        begin
            result[i] := byte((data[i + (length(data) - pLen)] and (not correct)) or (lrandom[i] and correct));
        end;

        fillbyte(data,length(data) ,0);
    end;

    {*
     * @throws InvalidCipherTextException if the decrypted block is not in PKCS1 format.
     }
    function TPKCS1Encoding.decodeBlock(inbuf:TBytes; inOff, inLen:integer):TBytes;
    var
      block,data:TBytes;
      start,i:integer;
      incorrectLength,badType:boolean;
      ltype:byte;
    begin
        {
         * If the length of the expected plaintext is known, we use a constant-time decryption.
         * If the decryption fails, we return a random value.
         }
        if (pLen <> -1) then
        begin
          exit(decodeBlockOrRandom(inbuf, inOff, inLen));
        end;

        block := engine.processBlock(inbuf, inOff, inLen);
        incorrectLength := (useStrictLength and (length(block) <> engine.getOutputBlockSize()));

        if (length(block) < getOutputBlockSize()) then
        begin
            data := blockBuffer;
        end
        else
        begin
            data := block;
        end;

        ltype := data[0];

        if (forPrivateKey) then
        begin
            badType := (ltype <> 2);
        end
        else
        begin
            badType := (ltype <> 1);
        end;

        //
        // find and extract the message block.
        //
        start := findStart(ltype, data);

        inc(start);           // data should start at the next byte

        if ((badType) or (start < HEADER_LENGTH)) then
        begin
            fillbyte(data,length(data) ,0);
            Raise exception.create('block incorrect');
        end;

        // if we get this far, it's likely to be a genuine encoding error
        if (incorrectLength) then
        begin
            fillbyte(data,length(data) ,0);
            Raise exception.create('block incorrect size');
        end;

        setlength(result,length(data) - start);;

        move(data[start], result[0], length(result));
    end;

    function TPKCS1Encoding.findStart(ltype:byte; block:Tbytes):integer;
    var
      start,i:integer;
      padErr:boolean;
      pad:byte;
    begin
        start := -1;
        padErr := false;

        for i := 1 to length(block)-1 do
        begin
            pad := block[i];

            if (pad = 0) and (start < 0) then
            begin
                start := i;
            end;
            padErr :=padErr or ((ltype = 1) and (start < 0) and (pad <> $ff));
        end;

        if (padErr) then
        begin
            exit(-1);
        end;

        result := start;
    end;
end.
