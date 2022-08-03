unit LongDigest;

interface
uses clpDigest,Pack;
type
{*
 * Base class for SHA-384 and SHA-512.
 }
  TLongDigest=class

		  const BYTE_LENGTH = 128;
    { SHA-384 and SHA-512 Constants
     * (represent the first 64 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     }
    const K:array [0..79] of int64 = (
$428a2f98d728ae22, $7137449123ef65cd, $b5c0fbcfec4d3b2f, $e9b5dba58189dbbc,
$3956c25bf348b538, $59f111f1b605d019, $923f82a4af194f9b, $ab1c5ed5da6d8118,
$d807aa98a3030242, $12835b0145706fbe, $243185be4ee4b28c, $550c7dc3d5ffb4e2,
$72be5d74f27b896f, $80deb1fe3b1696b1, $9bdc06a725c71235, $c19bf174cf692694,
$e49b69c19ef14ad2, $efbe4786384f25e3, $0fc19dc68b8cd5b5, $240ca1cc77ac9c65,
$2de92c6f592b0275, $4a7484aa6ea6e483, $5cb0a9dcbd41fbd4, $76f988da831153b5,
$983e5152ee66dfab, $a831c66d2db43210, $b00327c898fb213f, $bf597fc7beef0ee4,
$c6e00bf33da88fc2, $d5a79147930aa725, $06ca6351e003826f, $142929670a0e6e70,
$27b70a8546d22ffc, $2e1b21385c26c926, $4d2c6dfc5ac42aed, $53380d139d95b3df,
$650a73548baf63de, $766a0abb3c77b2a8, $81c2c92e47edaee6, $92722c851482353b,
$a2bfe8a14cf10364, $a81a664bbc423001, $c24b8b70d0f89791, $c76c51a30654be30,
$d192e819d6ef5218, $d69906245565a910, $f40e35855771202a, $106aa07032bbd1b8,
$19a4c116b8d2d0c8, $1e376c085141ab53, $2748774cdf8eeb99, $34b0bcb5e19b48a8,
$391c0cb3c5c95a63, $4ed8aa4ae3418acb, $5b9cca4f7763e373, $682e6ff3d6b2b8a3,
$748f82ee5defb2fc, $78a5636f43172f60, $84c87814a1f0ab72, $8cc702081a6439ec,
$90befffa23631e28, $a4506cebde82bde9, $bef9a3f7b2c67915, $c67178f2e372532b,
$ca273eceea26619c, $d186b8c721c0c207, $eada7dd6cde0eb1e, $f57d4f7fee6ed178,
$06f067aa72176fba, $0a637dc5a2c898a6, $113f9804bef90dae, $1b710b35131c471b,
$28db77f523047d84, $32caab7b40c72493, $3c9ebe0a15c9bebc, $431d67c49c100d4c,
$4cc5d4becb3e42b6, $597f299cfc657e2a, $5fcb6fab3ad6faec, $6c44198c4a475817
    );
      private
      xBuf : array [0..7] of byte;
      xBufOff,wOff:integer;

      
      W : array [0..79] of  int64;
			
      function  Ch(x,y,z:int64 ):int64;
      function Maj(x,y,z:int64):int64;
      function Sum0(x:int64):int64;
      function Sum1(x:int64):int64;
      function Sigma0(x:int64):int64;
      function Sigma1(x:int64):int64;
		
    protected    
		  H1, H2, H3, H4, H5, H6, H7, H8:int64;


      procedure copyIn(t:TLongDigest);
      procedure populateState(state:TByteArray);
      procedure restoreState(encodedState:TByteArray );
      function getEncodedStateSize():integer;
      procedure processWord(lin:TByteArray;inOff:integer);
      procedure adjustByteCounts();
      procedure processLength(lowW,hiW:int64);
      procedure processBlock();
		
    public
		  byteCount1,byteCount2:int64;
      constructor create();
      constructor create(t:TLongDigest);
      procedure update(lin:byte);
      procedure update(lin:TByteArray;inOff,len:integer);
      procedure finish();
      procedure reset();
      function getByteLength():integer;
			
  end;
implementation
    { SHA-384 and SHA-512 functions (as for SHA-256 but for longs) }
    function  TLongDigest.Ch(x,y,z:int64 ):int64;
    begin
        result := ((x and y) xor ((not x) and z));
    end;

    function TLongDigest.Maj(x,y,z:int64):int64;
    begin
        result := ((x and y) xor (x and z) xor (y and z));
    end;

    function TLongDigest.Sum0(x:int64):int64;
    begin
        result := ((x shl 36) or (x shr 28)) xor ((x shl 30) or (x shr 34)) xor ((x shl 25) or (x shr 39));
    end;

    function TLongDigest.Sum1(x:int64):int64;
    begin
        result := ((x shl 50) or (x shr 14)) xor ((x shl 46) or (x shr 18)) xor ((x shl 23) or (x shr 41));
    end;

    function TLongDigest.Sigma0(x:int64):int64;
    begin
        result := ((x shl 63) or (x shr 1)) xor ((x shl 56) or (x shr 8)) xor (x shr 7);
    end;

    function TLongDigest.Sigma1(x:int64):int64;
    begin
        result := ((x shl 45) or (x shr 19)) xor ((x shl 3) or (x shr 61)) xor (x shr 6);
    end;
    {*
     * Constructor for variable length word
     }
    constructor TLongDigest.create();
    begin
        xBufOff := 0;
        reset();
    end;

    {*
     * Copy constructor.  We are using copy constructors in place
     * of the Object.clone() interface as this interface is not
     * supported by J2ME.
     }
    constructor TLongDigest.create(t:TLongDigest);
    begin
        copyIn(t);
    end;

    procedure TLongDigest.copyIn(t:TLongDigest);
    begin
        move(t.xBuf[0], xBuf[0], length(t.xBuf));

        xBufOff := t.xBufOff;
        byteCount1 := t.byteCount1;
        byteCount2 := t.byteCount2;

        H1 := t.H1;
        H2 := t.H2;
        H3 := t.H3;
        H4 := t.H4;
        H5 := t.H5;
        H6 := t.H6;
        H7 := t.H7;
        H8 := t.H8;

        move(t.W[0], W[0], length(t.W));
        wOff := t.wOff;
    end;

    procedure TLongDigest.populateState(state:TByteArray);
		var
		  i:integer;
    begin
        move(xBuf[0], state[0], xBufOff);
        TPack.intToBigEndian(xBufOff, state, 8);
        TPack.longToBigEndian(byteCount1, state, 12);
        TPack.longToBigEndian(byteCount2, state, 20);
        TPack.longToBigEndian(H1, state, 28);
        TPack.longToBigEndian(H2, state, 36);
        TPack.longToBigEndian(H3, state, 44);
        TPack.longToBigEndian(H4, state, 52);
        TPack.longToBigEndian(H5, state, 60);
        TPack.longToBigEndian(H6, state, 68);
        TPack.longToBigEndian(H7, state, 76);
        TPack.longToBigEndian(H8, state, 84);

        TPack.intToBigEndian(wOff, state, 92);
        for i := 0 to wOff-1 do
        begin
            TPack.longToBigEndian(W[i], state, 96 + (i * 8));
        end;
    end;

    procedure TLongDigest.restoreState(encodedState:TByteArray );
		var
		  i:integer;
    begin
        xBufOff := TPack.bigEndianToInt(encodedState, 8);
        move(encodedState[0], xBuf[0], xBufOff);
        byteCount1 := TPack.bigEndianToLong(encodedState, 12);
        byteCount2 := TPack.bigEndianToLong(encodedState, 20);

        H1 := TPack.bigEndianToLong(encodedState, 28);
        H2 := TPack.bigEndianToLong(encodedState, 36);
        H3 := TPack.bigEndianToLong(encodedState, 44);
        H4 := TPack.bigEndianToLong(encodedState, 52);
        H5 := TPack.bigEndianToLong(encodedState, 60);
        H6 := TPack.bigEndianToLong(encodedState, 68);
        H7 := TPack.bigEndianToLong(encodedState, 76);
        H8 := TPack.bigEndianToLong(encodedState, 84);

        wOff := TPack.bigEndianToInt(encodedState, 92);
        for i := 0 to wOff-1 do
        begin
            W[i] := TPack.bigEndianToLong(encodedState, 96 + (i * 8));
        end;
    end;

    function TLongDigest.getEncodedStateSize():integer;
    begin
        result := 96 + (wOff * 8);
    end;
		


    procedure TLongDigest.processWord(lin:TByteArray;inOff:integer);
    begin
        W[wOff] := TPack.bigEndianToLong(lin, inOff);
        inc(wOff);
        if (wOff = 16) then
        begin
            processBlock();
        end;
    end;

    {*
     * adjust the byte counts so that byteCount2 represents the
     * upper long (less 3 bits) word of the byte count.
     }
    procedure TLongDigest.adjustByteCounts();
    begin
        if (byteCount1 > $1fffffffffffffff) then
        begin
            byteCount2 :=byteCount2 + (byteCount1 shr 61);
            byteCount1 :=byteCount1 and $1fffffffffffffff;
        end;
    end;

    procedure TLongDigest.processLength(lowW,hiW:int64);
    begin
        if (wOff > 14) then
        begin
            processBlock();
        end;

        W[14] := hiW;
        W[15] := lowW;
    end;

    procedure TLongDigest.processBlock();
		var
		  t,i:integer;
			a,b,c,d,e,f,g,h:int64;
    begin
        adjustByteCounts();

        //
        // expand 16 word block into 80 word blocks.
        //
        for t:= 16 to 79 do
        begin
            W[t] := Sigma1(W[t - 2]) + W[t - 7] + Sigma0(W[t - 15]) + W[t - 16];
        end;

        //
        // set up working variables.
        //
        a := H1;
        b := H2;
        c := H3;
        d := H4;
        e := H5;
        f := H6;
        g := H7;
        h := H8;

        t := 0;
        for i := 0 to 9 do
        begin
          // t := 8 * i
          h :=h + Sum1(e) + Ch(e, f, g) + K[t] + W[t];
					inc(t);
          d :=d + h;
          h :=h + Sum0(a) + Maj(a, b, c);

          // t := 8 * i + 1
          g :=g + Sum1(d) + Ch(d, e, f) + K[t] + W[t];
					inc(t);
          c :=c + g;
          g :=g + Sum0(h) + Maj(h, a, b);

          // t := 8 * i + 2
          f :=f + Sum1(c) + Ch(c, d, e) + K[t] + W[t];
					inc(t);
          b :=b + f;
          f :=f + Sum0(g) + Maj(g, h, a);

          // t := 8 * i + 3
          e :=e + Sum1(b) + Ch(b, c, d) + K[t] + W[t];
					inc(t);
          a :=a + e;
          e :=e + Sum0(f) + Maj(f, g, h);

          // t := 8 * i + 4
          d :=d + Sum1(a) + Ch(a, b, c) + K[t] + W[t];
					inc(t);
          h :=h + d;
          d :=d + Sum0(e) + Maj(e, f, g);

          // t := 8 * i + 5
          c :=c + Sum1(h) + Ch(h, a, b) + K[t] + W[t];
					inc(t);
          g :=g + c;
          c :=c + Sum0(d) + Maj(d, e, f);

          // t := 8 * i + 6
          b :=b + Sum1(g) + Ch(g, h, a) + K[t] + W[t];
					inc(t);
          f :=f + b;
          b :=b + Sum0(c) + Maj(c, d, e);

          // t := 8 * i + 7
          a :=a + Sum1(f) + Ch(f, g, h) + K[t] + W[t];
					inc(t);
          e :=e + a;
          a :=a + Sum0(b) + Maj(b, c, d);
        end;


        H1 :=H1 + a;
        H2 :=H2 + b;
        H3 :=H3 + c;
        H4 :=H4 + d;
        H5 :=H5 + e;
        H6 :=H6 + f;
        H7 :=H7 + g;
        H8 :=H8 + h;

        //
        // reset the offset and clean out the word buffer.
        //
        wOff := 0;
        for  i := 0 to 15 do
        begin
            W[i] := 0;
        end;
    end;
    procedure TLongDigest.update(lin:byte);
    begin
        xBuf[xBufOff] := lin;
        inc(xBufOff);
        if (xBufOff = length(xBuf)) then
        begin
            processWord(xBuf, 0);
            xBufOff := 0;
        end;

        inc(byteCount1);
    end;

    procedure TLongDigest.update(lin:TByteArray;inOff,len:integer);
    begin
        //
        // fill the current word
        //
        while (xBufOff <> 0) and (len > 0) do
        begin
            update(lin[inOff]);

            inc(inOff);
            dec(len);
        end;

        //
        // process whole words.
        //
        while (len > length(xBuf)) do
        begin
            processWord(lin, inOff);

            inOff :=inOff + length(xBuf);
            len :=len - length(xBuf);
            byteCount1 :=byteCount1 + length(xBuf);
        end;

        //
        // load in the remainder.
        //
        while (len > 0) do
        begin
            update(lin[inOff]);

            inc(inOff);
            dec(len);
        end;
    end;

    procedure TLongDigest.finish();
		var
		  lowBitLength,hiBitLength:int64;
    begin
        adjustByteCounts();

        lowBitLength := byteCount1 shl 3;
        hiBitLength := byteCount2;

        //
        // add the pad bytes.
        //
        update(byte(128));

        while (xBufOff <> 0) do
        begin
            update(0);
        end;

        processLength(lowBitLength, hiBitLength);

        processBlock();
    end;

    procedure TLongDigest.reset();
		var
		  i:integer;
    begin
        byteCount1 := 0;
        byteCount2 := 0;

        xBufOff := 0;
        for i := 0 to length(xBuf)-1 do
        begin
            xBuf[i] := 0;
        end;

        wOff := 0;
        for i := 0 to length(W)-1 do
        begin
            W[i] := 0;
        end;
    end;

    function TLongDigest.getByteLength():integer;
    begin
        result := BYTE_LENGTH;
    end;
end.
