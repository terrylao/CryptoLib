Unit Clppack ;
interface
uses Sysutils,ClpCryptoLibTypes;
  type
  TPack=class
  public
    class function  bigEndianToInt(bs:Tbytes; off:integer):integer;static;overload;
    class procedure bigEndianToInt(bs:Tbytes; off:integer; ns:TCryptoLibInt32Array );static; overload;
    class function intToBigEndian(n:integer ):TBytes;static;overload;
    class procedure intToBigEndian(n:integer; bs:Tbytes; off:integer);static;overload;
    class function intToBigEndian(ns:TCryptoLibInt32Array):TBytes;static;overload;
    class procedure intToBigEndian(ns:TCryptoLibInt32Array; bs:Tbytes; off:integer);static;overload;
    class function bigEndianToint64(bs:Tbytes; off:integer):int64;static;overload;
    class procedure bigEndianToint64(bs:Tbytes; off:integer; ns:TCryptoLibInt64Array);static;overload;
    class function int64ToBigEndian(n:int64):TBytes;static;overload;
    class procedure int64ToBigEndian(n:int64; bs:Tbytes; off:integer);static;overload;
    class function int64ToBigEndian(ns:TCryptoLibInt64Array):TBytes;static;overload;
    class procedure int64ToBigEndian(ns:TCryptoLibInt64Array; bs:Tbytes; off:integer);static;overload;
    class function littleEndianToInt(bs:Tbytes; off:integer):integer;static;overload;
    class procedure littleEndianToInt(bs:Tbytes; off:integer; ns:TCryptoLibInt32Array);static;overload;
    class procedure littleEndianToInt(bs:Tbytes; bOff:integer; ns:TCryptoLibInt32Array; nOff, count:integer);static;overload;
    class function intToLittleEndian(n:integer ):TBytes;static;overload;
    class procedure intToLittleEndian(n:integer; bs:Tbytes; off:integer);static;overload;
    class function intToLittleEndian(ns:TCryptoLibInt32Array):TBytes;static;overload;
    class procedure intToLittleEndian(ns:TCryptoLibInt32Array; bs:Tbytes; off:integer);static;overload;
    class function littleEndianToint64(bs:Tbytes; off:integer):int64;static;overload;
    class procedure littleEndianToint64(bs:Tbytes; off:integer; ns:TCryptoLibInt64Array);static;overload;
    class function int64ToLittleEndian(n:int64 ):TBytes;static;overload;
    class procedure int64ToLittleEndian(n:int64; bs:Tbytes; off:integer);static;overload;
    class function int64ToLittleEndian(ns:TCryptoLibInt64Array):TBytes;static;overload;
    class procedure int64ToLittleEndian(ns:TCryptoLibInt64Array; bs:Tbytes; off:integer);static;overload;
 
  end;
Implementation
    class function  TPack.bigEndianToInt(bs:Tbytes; off:integer):integer;
    begin
        result := bs[  off] shl 24;
        off:=off+1;
        result :=result or (bs[off] and $ff) shl 16;
        off:=off+1;
        result :=result or (bs[off] and $ff) shl 8;
        off:=off+1;
        result :=result or (bs[off] and $ff);
    end;

    class procedure TPack.bigEndianToInt(bs:Tbytes; off:integer; ns:TCryptoLibInt32Array );
    var
      i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := bigEndianToInt(bs, off);
            off :=off + 4;
        end;
    end;
    class procedure TPack.intToBigEndian(n:integer; bs:Tbytes; off:integer);
    begin
        bs[off] := byte(n shr 24);
        off:=off+1;
        bs[off] := byte(n shr 16);
        off:=off+1;
        bs[off] := byte(n shr  8);
        off:=off+1;
        bs[off] := byte(n       );
    end;

    class function TPack.intToBigEndian(n:integer ):TBytes;
    begin
        setlength(result,4);
        intToBigEndian(n, result, 0);
    end;



    class procedure TPack.intToBigEndian(ns:TCryptoLibInt32Array; bs:Tbytes; off:integer);
    var
      i:Integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            intToBigEndian(ns[i], bs, off);
            off :=off + 4;
        end;
    end;
    class function TPack.intToBigEndian(ns:TCryptoLibInt32Array):TBytes;
    begin
        setlength(result,4 * length(ns));
        intToBigEndian(ns, result, 0);
    end;
    class function TPack.bigEndianToint64(bs:Tbytes; off:integer):int64;
    var
      hi,lo:Integer;
    begin
        hi := bigEndianToInt(bs, off);
        lo := bigEndianToInt(bs, off + 4);
        result:= (int64(hi and int64($ffffffff)) shl 32) or int64(lo and int64($ffffffff));
    end;

    class procedure TPack.bigEndianToint64(bs:Tbytes; off:integer; ns:TCryptoLibInt64Array);
    var
      i:Integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := bigEndianToint64(bs, off);
            off :=off + 8;
        end;
    end;
    class procedure TPack.int64ToBigEndian(n:int64; bs:Tbytes; off:integer);
    begin
        intToBigEndian(integer(n shr 32), bs, off);
        intToBigEndian(integer(n and Int64($ffffffff)), bs, off + 4);
    end;
    class function TPack.int64ToBigEndian(n:int64):TBytes;
    begin
        setlength(result,8);
        int64ToBigEndian(n, result, 0);
    end;

    class procedure TPack.int64ToBigEndian(ns:TCryptoLibInt64Array; bs:Tbytes; off:integer);
    var
      i:Integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            int64ToBigEndian(ns[i], bs, off);
            off :=off + 8;
        end;
    end;
    class function TPack.int64ToBigEndian(ns:TCryptoLibInt64Array):TBytes;
    begin
        setlength(result,8 * length(ns));
        int64ToBigEndian(ns, result, 0);
    end;
    class function TPack.littleEndianToInt(bs:Tbytes; off:integer):integer;
    begin
        result := bs[  off] and $ff;
        result :=result or (bs[++off] and $ff) shl 8;
        result :=result or (bs[++off] and $ff) shl 16;
        result :=result or bs[++off] shl 24;
    end;

    class procedure TPack.littleEndianToInt(bs:Tbytes; off:integer; ns:TCryptoLibInt32Array);
    var
      i:Integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := littleEndianToInt(bs, off);
            off :=off + 4;
        end;
    end;

    class procedure TPack.littleEndianToInt(bs:Tbytes; bOff:integer; ns:TCryptoLibInt32Array; nOff, count:integer);
    var
      i:Integer;
    begin
        for i := 0 to count-1 do
        begin
            ns[nOff + i] := littleEndianToInt(bs, bOff);
            boff :=boff + 4;
        end;
    end;

    class procedure TPack.intToLittleEndian(n:integer; bs:Tbytes; off:integer);
    begin
        bs[  off] := byte(n       );
        off:=off+1;
        bs[off] := byte(n shr  8);
        off:=off+1;
        bs[off] := byte(n shr 16);
        off:=off+1;
        bs[off] := byte(n shr 24);
    end;
    class function TPack.intToLittleEndian(n:integer ):TBytes;
    begin
        setlength(result,4);
        intToLittleEndian(n, result, 0);
    end;

    class procedure TPack.intToLittleEndian(ns:TCryptoLibInt32Array; bs:Tbytes; off:integer);
    var
      i:integer;
    begin
        for i := 0 to length(ns) -1 do
        begin
            intToLittleEndian(ns[i], bs, off);
            off :=off + 4;
        end;
    end;
    class function TPack.intToLittleEndian(ns:TCryptoLibInt32Array):TBytes;
    begin
        setlength(result,4 * length(ns));
        intToLittleEndian(ns, result, 0);
    end;
    class function TPack.littleEndianToint64(bs:Tbytes; off:integer):int64;
    var
      lo,hi:integer;
    begin
        lo := littleEndianToInt(bs, off);
        hi := littleEndianToInt(bs, off + 4);
        result := (int64(hi and Int64($ffffffff)) shl 32) or int64(lo and Int64($ffffffff));
    end;

    class procedure TPack.littleEndianToint64(bs:Tbytes; off:integer; ns:TCryptoLibInt64Array);
    var
      i:Integer;
    begin
        for i := 0 to length(ns) -1 do
        begin
            ns[i] := littleEndianToint64(bs, off);
            off :=off + 8;
        end;
    end;

    class procedure TPack.int64ToLittleEndian(n:int64; bs:Tbytes; off:integer);
    begin
        intToLittleEndian(integer(n and Int64($ffffffff)), bs, off);
        intToLittleEndian(integer(n shr 32), bs, off + 4);
    end;
    class function TPack.int64ToLittleEndian(n:int64 ):TBytes;
    begin
        setlength(result,8);
        int64ToLittleEndian(n, result, 0);
    end;


    class procedure TPack.int64ToLittleEndian(ns:TCryptoLibInt64Array; bs:Tbytes; off:integer);
    var
      i:Integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            int64ToLittleEndian(ns[i], bs, off);
            off :=off + 8;
        end;
    end;
    class function TPack.int64ToLittleEndian(ns:TCryptoLibInt64Array):TBytes;
    begin
        setlength(result,8 * length(ns));
        int64ToLittleEndian(ns, result, 0);
    end;
end.
