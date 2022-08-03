Unit ClpDESEngine;
{*
 * a class that provides a basic DES engine.
 }
interface

uses Sysutils,clpIBlockCipher,Clppack,ClpCryptoLibTypes,ClpICipherParameters,ClpIKeyParameter;
const
  BLOCK_SIZE = 8;
  {*
   * what follows is mainly taken from 'Applied Cryptography', by
   * Bruce Schneier, however it also bears great resemblance to Richard
   * Outerbridge's D3DES...
   }

//    private static final short[]    Df_Key :=
//        begin
//            $01,$23,$45,$67,$89,$ab,$cd,$ef,
//            $fe,$dc,$ba,$98,$76,$54,$32,$10,
//            $89,$ab,$cd,$ef,$01,$23,$45,$67
//        end;;
  bytebit: array [0 .. 7] of byte=
      (
          //0200, 0100, 040, 020, 010, 04, 02, 01
          128, 64, 32, 16, 8, 4, 2, 1
      );

  bigbyte : array [0 .. 23] of Uint32=
      (
          $800000, $400000, $200000, $100000,
          $80000,  $40000,  $20000,  $10000,
          $8000,      $4000,   $2000,   $1000,
          $800,    $400,    $200,    $100,
          $80,      $40,        $20,     $10,
          $8,      $4,      $2,      $1
      );

  {
   * Use the key schedule specified in the Standard (ANSI X3.92-1981).
   }

  pc1 : array [0 .. 55] of Byte =
      (
          56, 48, 40, 32, 24, 16,  8,   0, 57, 49, 41, 33, 25, 17,
           9,  1, 58, 50, 42, 34, 26,  18, 10,  2, 59, 51, 43, 35,
          62, 54, 46, 38, 30, 22, 14,   6, 61, 53, 45, 37, 29, 21,
          13,  5, 60, 52, 44, 36, 28,  20, 12,  4, 27, 19, 11,  3
      );

  totrot : array [0 .. 15] of Byte =
      (
          1, 2, 4, 6, 8, 10, 12, 14,
          15, 17, 19, 21, 23, 25, 27, 28
      );

  pc2 : array [0 .. 47] of Byte =
      (
          13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
          22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
          40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
          43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
      );

  SP1 : array [0 .. 63] of Uint32=(
      $01010400, $00000000, $00010000, $01010404,
      $01010004, $00010404, $00000004, $00010000,
      $00000400, $01010400, $01010404, $00000400,
      $01000404, $01010004, $01000000, $00000004,
      $00000404, $01000400, $01000400, $00010400,
      $00010400, $01010000, $01010000, $01000404,
      $00010004, $01000004, $01000004, $00010004,
      $00000000, $00000404, $00010404, $01000000,
      $00010000, $01010404, $00000004, $01010000,
      $01010400, $01000000, $01000000, $00000400,
      $01010004, $00010000, $00010400, $01000004,
      $00000400, $00000004, $01000404, $00010404,
      $01010404, $00010004, $01010000, $01000404,
      $01000004, $00000404, $00010404, $01010400,
      $00000404, $01000400, $01000400, $00000000,
      $00010004, $00010400, $00000000, $01010004
  );

  SP2 : array [0 .. 63] of Uint32=(
      $80108020, $80008000, $00008000, $00108020,
      $00100000, $00000020, $80100020, $80008020,
      $80000020, $80108020, $80108000, $80000000,
      $80008000, $00100000, $00000020, $80100020,
      $00108000, $00100020, $80008020, $00000000,
      $80000000, $00008000, $00108020, $80100000,
      $00100020, $80000020, $00000000, $00108000,
      $00008020, $80108000, $80100000, $00008020,
      $00000000, $00108020, $80100020, $00100000,
      $80008020, $80100000, $80108000, $00008000,
      $80100000, $80008000, $00000020, $80108020,
      $00108020, $00000020, $00008000, $80000000,
      $00008020, $80108000, $00100000, $80000020,
      $00100020, $80008020, $80000020, $00100020,
      $00108000, $00000000, $80008000, $00008020,
      $80000000, $80100020, $80108020, $00108000
  );

  SP3 : array [0 .. 63] of Uint32=(
      $00000208, $08020200, $00000000, $08020008,
      $08000200, $00000000, $00020208, $08000200,
      $00020008, $08000008, $08000008, $00020000,
      $08020208, $00020008, $08020000, $00000208,
      $08000000, $00000008, $08020200, $00000200,
      $00020200, $08020000, $08020008, $00020208,
      $08000208, $00020200, $00020000, $08000208,
      $00000008, $08020208, $00000200, $08000000,
      $08020200, $08000000, $00020008, $00000208,
      $00020000, $08020200, $08000200, $00000000,
      $00000200, $00020008, $08020208, $08000200,
      $08000008, $00000200, $00000000, $08020008,
      $08000208, $00020000, $08000000, $08020208,
      $00000008, $00020208, $00020200, $08000008,
      $08020000, $08000208, $00000208, $08020000,
      $00020208, $00000008, $08020008, $00020200
  );

  SP4 : array [0 .. 63] of Uint32=(
      $00802001, $00002081, $00002081, $00000080,
      $00802080, $00800081, $00800001, $00002001,
      $00000000, $00802000, $00802000, $00802081,
      $00000081, $00000000, $00800080, $00800001,
      $00000001, $00002000, $00800000, $00802001,
      $00000080, $00800000, $00002001, $00002080,
      $00800081, $00000001, $00002080, $00800080,
      $00002000, $00802080, $00802081, $00000081,
      $00800080, $00800001, $00802000, $00802081,
      $00000081, $00000000, $00000000, $00802000,
      $00002080, $00800080, $00800081, $00000001,
      $00802001, $00002081, $00002081, $00000080,
      $00802081, $00000081, $00000001, $00002000,
      $00800001, $00002001, $00802080, $00800081,
      $00002001, $00002080, $00800000, $00802001,
      $00000080, $00800000, $00002000, $00802080
  );

  SP5 : array [0 .. 63] of Uint32=(
      $00000100, $02080100, $02080000, $42000100,
      $00080000, $00000100, $40000000, $02080000,
      $40080100, $00080000, $02000100, $40080100,
      $42000100, $42080000, $00080100, $40000000,
      $02000000, $40080000, $40080000, $00000000,
      $40000100, $42080100, $42080100, $02000100,
      $42080000, $40000100, $00000000, $42000000,
      $02080100, $02000000, $42000000, $00080100,
      $00080000, $42000100, $00000100, $02000000,
      $40000000, $02080000, $42000100, $40080100,
      $02000100, $40000000, $42080000, $02080100,
      $40080100, $00000100, $02000000, $42080000,
      $42080100, $00080100, $42000000, $42080100,
      $02080000, $00000000, $40080000, $42000000,
      $00080100, $02000100, $40000100, $00080000,
      $00000000, $40080000, $02080100, $40000100
  );

  SP6 : array [0 .. 63] of Uint32=(
      $20000010, $20400000, $00004000, $20404010,
      $20400000, $00000010, $20404010, $00400000,
      $20004000, $00404010, $00400000, $20000010,
      $00400010, $20004000, $20000000, $00004010,
      $00000000, $00400010, $20004010, $00004000,
      $00404000, $20004010, $00000010, $20400010,
      $20400010, $00000000, $00404010, $20404000,
      $00004010, $00404000, $20404000, $20000000,
      $20004000, $00000010, $20400010, $00404000,
      $20404010, $00400000, $00004010, $20000010,
      $00400000, $20004000, $20000000, $00004010,
      $20000010, $20404010, $00404000, $20400000,
      $00404010, $20404000, $00000000, $20400010,
      $00000010, $00004000, $20400000, $00404010,
      $00004000, $00400010, $20004010, $00000000,
      $20404000, $20000000, $00400010, $20004010
  );

  SP7 : array [0 .. 63] of Uint32=(
      $00200000, $04200002, $04000802, $00000000,
      $00000800, $04000802, $00200802, $04200800,
      $04200802, $00200000, $00000000, $04000002,
      $00000002, $04000000, $04200002, $00000802,
      $04000800, $00200802, $00200002, $04000800,
      $04000002, $04200000, $04200800, $00200002,
      $04200000, $00000800, $00000802, $04200802,
      $00200800, $00000002, $04000000, $00200800,
      $04000000, $00200800, $00200000, $04000802,
      $04000802, $04200002, $04200002, $00000002,
      $00200002, $04000000, $04000800, $00200000,
      $04200800, $00000802, $00200802, $04200800,
      $00000802, $04000002, $04200802, $04200000,
      $00200800, $00000000, $00000002, $04200802,
      $00000000, $00200802, $04200000, $00000800,
      $04000002, $04000800, $00000800, $00200002
  );

  SP8 : array [0 .. 63] of Uint32=(
      $10001040, $00001000, $00040000, $10041040,
      $10000000, $10001040, $00000040, $10000000,
      $00040040, $10040000, $10041040, $00041000,
      $10041000, $00041040, $00001000, $00000040,
      $10040000, $10000040, $10001000, $00001040,
      $00041000, $00040040, $10040040, $10041000,
      $00001040, $00000000, $00000000, $10040040,
      $10000040, $10001000, $00041040, $00040000,
      $00041040, $00040000, $10041000, $00001000,
      $00000040, $10040040, $00001000, $00041040,
      $10001000, $00000040, $10000040, $10040000,
      $10040040, $10000000, $00040000, $10001040,
      $00000000, $10041040, $00040040, $10000040,
      $10040000, $10001000, $10001040, $00000000,
      $10041040, $00041000, $00041000, $00001040,
      $00001040, $00040040, $10000000, $10041000
  );
type
  TDESEngine=class(TInterfacedObject,IBlockCipher)
    private
      workingKey:TCryptoLibUInt32Array;


    function GetIsPartialBlockOkay: Boolean;
    protected
      procedure desFunc(wKey:TCryptoLibUInt32Array;inbuf:tbytes;inOff:integer;outbuf:tbytes;outOff:integer);
      function generateWorkingKey(encrypting:boolean ;key:Tbytes ):TCryptoLibUInt32Array;
    public
      constructor create();
      procedure init(encrypting:boolean;const params:ICipherParameters);
      function getAlgorithmName():String;
      function getBlockSize():integer;
      procedure reset();
      function getCurrentKey():TCryptoLibByteArray;
      function getCurrentIV():TCryptoLibByteArray;virtual;
      procedure changeIV(modifier:TCryptoLibByteArray);
      function processBlock(const inbuf:TBytes;inOff:integer;const outbuf:TBytes;outOff:integer):integer;
      property AlgorithmName: String read GetAlgorithmName;
      property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
end;
Implementation

    {*
     * standard constructor.
     }
    constructor TDESEngine.create();
    begin
    end;

    {*
     * initialise a DES cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     }
    procedure TDESEngine.init(encrypting:boolean;const params:ICipherParameters);
    var
      keyParameter: IKeyParameter;
    begin
        if  Supports(params, IKeyParameter, keyParameter) then
        begin
            if (length(keyParameter.getKey()) > 8) then
            begin
                Raise Exception.create('DES key too long - should be 8 bytes');
            end;
            
            workingKey := generateWorkingKey(encrypting,keyParameter.getKey());

            exit;
        end;

        Raise Exception.create('invalid parameter passed to DES init - ');
    end;

    function TDESEngine.getAlgorithmName():String;
    begin
        result := 'DES';
    end;

    function TDESEngine.getBlockSize():integer;
    begin
        result := BLOCK_SIZE;
    end;

    function TDESEngine.processBlock(const inbuf:TBytes;inOff:integer;const outbuf:TBytes;outOff:integer):integer;
    begin
        if (workingKey = nil) then
        begin
            Raise Exception.create('DES engine not initialised');
        end;

        if ((inOff + BLOCK_SIZE) > length(inbuf)) then
        begin
            Raise Exception.create('input buffer too short');
        end;

        if ((outOff + BLOCK_SIZE) > length(outbuf)) then
        begin
            Raise Exception.create('output buffer too short');
        end;

        desFunc(workingKey, inbuf, inOff, outbuf, outOff);

        result := BLOCK_SIZE;
    end;

    procedure TDESEngine.reset();
    begin
    end;



    {*
     * generate an integer based working key based on our secret key
     * and what we processing we are planning to do.
     *
     * Acknowledgements for this routine go to James Gillogly andamp; Phil Karn.
     *         (whoever, and wherever they are!).
     }
    function TDESEngine.generateWorkingKey(encrypting:boolean ;key:Tbytes ):TCryptoLibUInt32Array;
    var
      newKey:TCryptoLibUInt32Array;
      pc1m,PC1R:array of byte;
      i,j,l,m,n,i1,i2:integer;
      KS         : array [0..7] of Byte;
    begin
        setlength(newKey,32);
        setlength(pc1m,56);
        setlength(PC1R,56);
{
        for j := 0 to 55 do
        begin
            l := pc1[j];

            pc1m[j] := ((key[l shr 3] and bytebit[l and 07]) <> 0);
        end;

        for i := 0 to 15 do
        begin
            if (encrypting) then
            begin
                m := i shl 1;
            end
            else
            begin
                m := (15 - i) shl 1;
            end;

            n := m + 1;
            newKey[m] := 0;
            newKey[n] := 0;

            for j := 0 to 27 do
            begin
                l := j + totrot[i];
                if (l < 28) then
                begin
                    pcr[j] := pc1m[l];
                end
                else
                begin
                    pcr[j] := pc1m[l - 28];
                end;
            end;

            for j := 28 to 55 do
            begin
                l := j + totrot[i];
                if (l < 56) then
                begin
                    pcr[j] := pc1m[l];
                end
                else
                begin
                    pcr[j] := pc1m[l - 28];
                end;
            end;

            for j := 0 to 24 do
            begin
                if (pcr[pc2[j]]) then
                begin
                    newKey[m] :=newKey[m] or bigbyte[j];
                end;

                if (pcr[pc2[j + 24]]) then
                begin
                    newKey[n] :=newKey[n] or bigbyte[j];
                end;
            end;
        end;

        //
        // store the processed key
        //
        i := 0;
        while (i <> 32) do
        begin
            i1 := newKey[i];
            i2 := newKey[i + 1];

            newKey[i] := ((i1 and $00fc0000) shl 6) or ((i1 and $00000fc0) shl 10)
                                   or ((i2 and $00fc0000) shr 10) or ((i2 and $00000fc0) shr 6);

            newKey[i + 1] := ((i1 and $0003f000) shl 12) or ((i1 and $0000003f) shl 16)
                                   or ((i2 and $0003f000) shr 4) or (i2 and $0000003f);
            i :=i + 2;
        end;
}
      {convert PC1 to bits of key}
      for J := 0 to 55 do begin
        L := PC1[J];
        M := L mod 8;
        PC1M[J] := Ord((Key[L div 8] and bytebit[M]) <> 0);
      end;

      {key chunk for each iteration}
      for I := 0 to 15 do begin
        {rotate PC1 the right amount}
        for J := 0 to 27 do begin
          L := J + TotRot[I];
          if (L < 28) then begin
            PC1R[J] := PC1M[L];
            PC1R[J + 28] := PC1M[L + 28];
          end else begin
            PC1R[J] := PC1M[L - 28];
            PC1R[J + 28] := PC1M[L];
          end;
        end;

        {select bits individually}
        FillChar(KS, SizeOf(KS), 0);
        for J := 0 to 47 do
          if Boolean(PC1R[PC2[J]]) then begin
            L := J div 6;
            KS[L] := KS[L] or bytebit[J mod 6] shr 2;
          end;

        {now convert to odd/even interleaved form for use in F}
        if encrypting then begin
          newKey[I * 2] := (LongInt(KS[0]) shl 24) or (LongInt(KS[2]) shl 16) or
            (LongInt(KS[4]) shl 8) or (LongInt(KS[6]));
          newKey[I * 2 + 1] := (LongInt(KS[1]) shl 24) or (LongInt(KS[3]) shl 16) or
            (LongInt(KS[5]) shl 8) or (LongInt(KS[7]));
        end else begin
          newKey[31 - (I * 2 + 1)] := (LongInt(KS[0]) shl 24) or (LongInt(KS[2]) shl 16) or
            (LongInt(KS[4]) shl 8) or (LongInt(KS[6]));
          newKey[31 - (I * 2)] := (LongInt(KS[1]) shl 24) or (LongInt(KS[3]) shl 16) or
            (LongInt(KS[5]) shl 8) or (LongInt(KS[7]));
        end;
      end;
      result := newKey;
    end;

    {*
     * the DES engine.
     }
    procedure TDESEngine.desFunc(wKey:TCryptoLibUInt32Array;inbuf:tbytes;inOff:integer;outbuf:tbytes;outOff:integer);
    var
      work, right, left,fval,round:DWord;
    begin
        left := TPack.bigEndianToInt(inbuf, inOff);
        right := TPack.bigEndianToInt(inbuf, inOff + 4);

        work := ((left shr 4) xor right) and $0f0f0f0f;
        right :=right xor work;
        left :=left xor (work shl 4);
        work := ((left shr 16) xor right) and $0000ffff;
        right :=right xor work;
        left :=left xor (work shl 16);
        work := ((right shr 2) xor left) and $33333333;
        left :=left xor work;
        right :=right xor (work shl 2);
        work := ((right shr 8) xor left) and $00ff00ff;
        left :=left xor work;
        right :=right xor (work shl 8);
        right := (right shl 1) or (right shr 31);
        work := (left xor right) and $aaaaaaaa;
        left :=left xor work;
        right :=right xor work;
        left := (left shl 1) or (left shr 31);

        for  round := 0 to 7 do
        begin
            work  := (right shl 28) or (right shr 4);
            work :=work xor wKey[round * 4 + 0];
            fval  := SP7[ work      and $3f];
            fval :=fval or SP5[(work shr  8) and $3f];
            fval :=fval or SP3[(work shr 16) and $3f];
            fval :=fval or SP1[(work shr 24) and $3f];
            work  := right xor wKey[round * 4 + 1];
            fval :=fval or SP8[ work      and $3f];
            fval :=fval or SP6[(work shr  8) and $3f];
            fval :=fval or SP4[(work shr 16) and $3f];
            fval :=fval or SP2[(work shr 24) and $3f];
            left :=left xor fval;
            work  := (left shl 28) or (left shr 4);
            work :=work xor wKey[round * 4 + 2];
            fval  := SP7[ work      and $3f];
            fval :=fval or SP5[(work shr  8) and $3f];
            fval :=fval or SP3[(work shr 16) and $3f];
            fval :=fval or SP1[(work shr 24) and $3f];
            work  := left xor wKey[round * 4 + 3];
            fval :=fval or SP8[ work      and $3f];
            fval :=fval or SP6[(work shr  8) and $3f];
            fval :=fval or SP4[(work shr 16) and $3f];
            fval :=fval or SP2[(work shr 24) and $3f];
            right :=right xor fval;
        end;

        right := (right shl 31) or (right shr 1);
        work := (left xor right) and $aaaaaaaa;
        left :=left xor work;
        right :=right xor work;
        left := (left shl 31) or (left shr 1);
        work := ((left shr 8) xor right) and $00ff00ff;
        right :=right xor work;
        left :=left xor (work shl 8);
        work := ((left shr 2) xor right) and $33333333;
        right :=right xor work;
        left :=left xor (work shl 2);
        work := ((right shr 16) xor left) and $0000ffff;
        left :=left xor work;
        right :=right xor (work shl 16);
        work := ((right shr 4) xor left) and $0f0f0f0f;
        left :=left xor work;
        right :=right xor (work shl 4);

        TPack.intToBigEndian(right, outbuf, outOff);
        TPack.intToBigEndian(left, outbuf, outOff + 4);
    end;
    function TDESEngine.GetIsPartialBlockOkay: Boolean;
    begin
      result := false;
    end;
    function TDESEngine.getCurrentIV():TCryptoLibByteArray;
    begin
      // nothing to do.
    end;
    function TDESEngine.getCurrentKey():TCryptoLibByteArray;
    begin
      //result:=workingKey;
    end;
    procedure TDESEngine.changeIV(modifier:TCryptoLibByteArray);
    begin
      // nothing to do.
    end;
end.
