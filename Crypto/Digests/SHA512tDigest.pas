unit SHA512tDigest;

interface
uses Pack,LongDigest,sysutils,Math;
type
  TByteArray = Array of Byte;
{*
 * FIPS 180-4 implementation of SHA-512/t
 }
  TSHA512tDigest=class(TLongDigest)

    public
      constructor create(bitLength:integer);
      constructor create(encodedState:TByteArray);
      function getAlgorithmName():String;
      function getDigestSize():integer;
      function doFinal(lout:TByteArray ;outOff:integer ):integer;
      procedure reset();
      function getEncodedState():TByteArray;
    private 
		  digestLength:integer;      // non-final due to old flow analyser.

      H1t, H2t, H3t, H4t, H5t, H6t, H7t, H8t:int64;
      function readDigestLength(encodedState:TByteArray):integer;
      procedure tIvGenerate(bitLength:integer);
      procedure longToBigEndian(n:int64; bs:TByteArray; max,off:integer);
      procedure intToBigEndian(n:integer; bs:TByteArray; max,off:integer);

  end;
implementation
    {*
     * Standard constructor
     }
    constructor TSHA512tDigest.create(bitLength:integer);
    begin
        if (bitLength >= 512) then
        begin
            Raise  exception.create('bitLength cannot be >= 512');
        end;

        if (bitLength mod 8 <> 0) then
        begin
            Raise  exception.create('bitLength needs to be a multiple of 8');
        end;

        if (bitLength = 384) then
        begin
            Raise  exception.create('bitLength cannot be 384 use SHA384 instead');
        end;

        digestLength := bitLength div 8;

        tIvGenerate(digestLength * 8);

        reset();
    end;

    {*
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     }

    constructor TSHA512tDigest.create(encodedState:TByteArray);
    begin
        create(readDigestLength(encodedState));
        restoreState(encodedState);
    end;
    function TSHA512tDigest.getAlgorithmName():String;
    begin
        result := 'SHA-512/' + Integer.toString(digestLength * 8);
    end;


    function TSHA512tDigest.getDigestSize():integer;
    begin
        result := digestLength;
    end;

    function TSHA512tDigest.doFinal(lout:TByteArray ;outOff:integer ):integer;
    begin
        finish();

        longToBigEndian(H1, lout, outOff, digestLength);
        longToBigEndian(H2, lout, outOff + 8, digestLength - 8);
        longToBigEndian(H3, lout, outOff + 16, digestLength - 16);
        longToBigEndian(H4, lout, outOff + 24, digestLength - 24);
        longToBigEndian(H5, lout, outOff + 32, digestLength - 32);
        longToBigEndian(H6, lout, outOff + 40, digestLength - 40);
        longToBigEndian(H7, lout, outOff + 48, digestLength - 48);
        longToBigEndian(H8, lout, outOff + 56, digestLength - 56);

        reset();

        result := digestLength;
    end;

    {*
     * reset the chaining variables
     }
    procedure TSHA512tDigest.reset();
    begin
        inherited reset();

        {
         * initial hash values use the iv generation algorithm for t.
         }
        H1 := H1t;
        H2 := H2t;
        H3 := H3t;
        H4 := H4t;
        H5 := H5t;
        H6 := H6t;
        H7 := H7t;
        H8 := H8t;
    end;

    function TSHA512tDigest.getEncodedState():TByteArray;
    var
		  baseSize:integer;
    begin
        baseSize := getEncodedStateSize();
        setlength(result,baseSize + 4);
        populateState(result);
        TPack.intToBigEndian(digestLength * 8, result, baseSize);
    end;
      function TSHA512tDigest.readDigestLength(encodedState:TByteArray):integer;
      begin
          result := TPack.bigEndianToInt(encodedState, length(encodedState) - 4);
      end;
			
      procedure TSHA512tDigest.tIvGenerate(bitLength:integer);
      begin
          H1 := $6a09e667f3bcc908 xor $a5a5a5a5a5a5a5a5;
          H2 := $bb67ae8584caa73b xor $a5a5a5a5a5a5a5a5;
          H3 := $3c6ef372fe94f82b xor $a5a5a5a5a5a5a5a5;
          H4 := $a54ff53a5f1d36f1 xor $a5a5a5a5a5a5a5a5;
          H5 := $510e527fade682d1 xor $a5a5a5a5a5a5a5a5;
          H6 := $9b05688c2b3e6c1f xor $a5a5a5a5a5a5a5a5;
          H7 := $1f83d9abfb41bd6b xor $a5a5a5a5a5a5a5a5;
          H8 := $5be0cd19137e2179 xor $a5a5a5a5a5a5a5a5;

          update(byte($53));
          update(byte($48));
          update(byte($41));
          update(byte($2D));
          update(byte($35));
          update(byte($31));
          update(byte($32));
          update(byte($2F));

          if (bitLength > 100) then
          begin
              update(byte(bitLength div 100 + $30));
              bitLength := bitLength mod 100;
              update(byte(bitLength div 10 + $30));
              bitLength := bitLength mod 10;
              update(byte(bitLength + $30));
          end
          else if (bitLength > 10) then
          begin
              update(byte(bitLength div 10 + $30));
              bitLength := bitLength mod 10;
              update(byte(bitLength + $30));
          end
          else
          begin
              update(byte(bitLength + $30));
          end;

          finish();

          H1t := H1;
          H2t := H2;
          H3t := H3;
          H4t := H4;
          H5t := H5;
          H6t := H6;
          H7t := H7;
          H8t := H8;
      end;

      procedure TSHA512tDigest.longToBigEndian(n:int64; bs:TByteArray; max,off:integer);
      begin
          if (max > 0) then
          begin
              intToBigEndian(integer(n shr 32), bs, off, max);
              if (max > 4) then
              begin
                  intToBigEndian(integer(n and $ffffffff), bs, off + 4, max - 4);
              end;
          end;
      end;

      procedure TSHA512tDigest.intToBigEndian(n:integer; bs:TByteArray; max,off:integer);
      var
			  num,shift:integer;
      begin
          num := min(4, max);
					dec(num);
          while (num >= 0) do
          begin
              shift := 8 * (3 - num);
              bs[off + num] := byte(n shr shift);
							dec(num);
          end;
      end;
end.
