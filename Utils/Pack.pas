unit Pack;
interface
type
  TByteArray = Array of Byte;
  TINTArray = Array of integer;
	TINT64Array = Array of int64;
{*
 * Utility methods for converting byte arrays into ints and longs, and back again.
 }
  TPack=class
	 public
    class function  bigEndianToShort(bs:TByteArray ; off:integer):int16;
    class function  bigEndianToInt(bs:TByteArray ; off:integer):integer;
    class procedure bigEndianToInt(bs:TByteArray ; off:integer; ns:TINTArray);
    class procedure bigEndianToInt(bs:TByteArray ; off:integer; ns:TINTArray; nsOff, nsLen:integer);
    class function  intToBigEndian(n:integer):TByteArray ;
    class procedure intToBigEndian(n:integer; bs:TByteArray ; off:integer);
    class function  intToBigEndian(ns:TINTArray):TByteArray ;
    class procedure intToBigEndian(ns:TINTArray; bs:TByteArray ; off:integer);
    class procedure intToBigEndian(ns:TINTArray; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    class function  bigEndianToLong(bs:TByteArray ; off:integer):int64;
    class procedure bigEndianToLong(bs:TByteArray ; off:integer; ns:TINT64Array);
    class procedure bigEndianToLong(bs:TByteArray ; bsOff:integer; ns:TINT64Array; nsOff, nsLen:integer);
    class function  longToBigEndian(n:int64):TByteArray ;
    class procedure  longToBigEndian(n:int64; bs:TByteArray ; off:integer);
    class function  longToBigEndian(ns:TINT64Array):TByteArray ;
    class procedure longToBigEndian(ns:TINT64Array; bs:TByteArray ; off:integer);
    class procedure longToBigEndian(ns:TINT64Array; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    class procedure longToBigEndian( value:int64; bs:TByteArray ; off, bytes:integer);
    class function  littleEndianToShort(bs:TByteArray ; off:integer):int16;
    class function  littleEndianToInt(bs:TByteArray ; off:integer):integer;
    class procedure littleEndianToInt(bs:TByteArray ; off:integer; ns:TINTArray);
    class procedure littleEndianToInt(bs:TByteArray ; bOff:integer; ns:TINTArray; nOff, count:integer);
    class function  littleEndianToInt(bs:TByteArray ; off, count:integer):TINTArray;
    class function  shortToLittleEndian(n:int16):TByteArray ;
    class procedure shortToLittleEndian(n:int16; bs:TByteArray ; off:integer);
    class function  shortToBigEndian(n:int16):TByteArray ;
    class procedure shortToBigEndian(n:int16; bs:TByteArray ; off:integer);
    class function  intToLittleEndian(n:integer):TByteArray ;
    class procedure intToLittleEndian(n:integer; bs:TByteArray ; off:integer);
    class function  intToLittleEndian(ns:TINTArray):TByteArray ;
    class procedure intToLittleEndian(ns:TINTArray; bs:TByteArray ; off:integer);
		class procedure intToLittleEndian(ns:TINTArray; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    class function  littleEndianToLong(bs:TByteArray ; off:integer):int64;
    class procedure littleEndianToLong(bs:TByteArray ; off:integer; ns:TINT64Array);
    class procedure littleEndianToLong(bs:TByteArray ; bsOff:integer; ns:TINT64Array; nsOff, nsLen:integer);
    class function  longToLittleEndian(n:int64):TByteArray ;
    class procedure longToLittleEndian(n:int64; bs:TByteArray ; off:integer);
    class function  longToLittleEndian(ns:TINT64Array):TByteArray ;
    class procedure longToLittleEndian(ns:TINT64Array; bs:TByteArray ; off:integer);
    class procedure longToLittleEndian(ns:TINT64Array; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
  end;
implementation
    class function TPack.bigEndianToShort(bs:TByteArray ; off:integer):int16;
		var
		  n:integer;
    begin
        n := (bs[off] and $ff) shl 8;
				inc(off);
        n :=n or (bs[off] and $ff);
        result := n;
    end;

    class function TPack.bigEndianToInt(bs:TByteArray ; off:integer):integer;
		var
		  n:integer;
    begin
        n := bs[off] shl 24;
				inc(off);
        n :=n or (bs[off] and $ff) shl 16;
				inc(off);
        n :=n or (bs[off] and $ff) shl 8;
				inc(off);
        n :=n or (bs[off] and $ff);
        result := n;
    end;

    class procedure TPack.bigEndianToInt(bs:TByteArray ; off:integer; ns:TINTArray);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := bigEndianToInt(bs, off);
            off   :=off + 4;
        end;
    end;

    class procedure TPack.bigEndianToInt(bs:TByteArray ; off:integer; ns:TINTArray; nsOff, nsLen:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            ns[nsOff + i] := bigEndianToInt(bs, off);
            off   :=off + 4;
        end;
    end;

    class function TPack.intToBigEndian(n:integer):TByteArray ;
    begin
				setlength(result,4);
        intToBigEndian(n, result, 0);
    end;

    class procedure TPack.intToBigEndian(n:integer; bs:TByteArray ; off:integer);
    begin
        bs[off] := byte(n shr 24);
				inc(off);
        bs[off] := byte(n shr 16);
				inc(off);
        bs[off] := byte(n shr 8);
				inc(off);
        bs[off] := byte(n);
    end;

    class function TPack.intToBigEndian(ns:TINTArray):TByteArray ;
    begin
        setlength(result,4 * length(ns));
        intToBigEndian(ns, result, 0);
    end;

    class procedure TPack.intToBigEndian(ns:TINTArray; bs:TByteArray ; off:integer);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            intToBigEndian(ns[i], bs, off);
            off := off + 4;
        end;
    end;

    class procedure TPack.intToBigEndian(ns:TINTArray; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            intToBigEndian(ns[nsOff + i], bs, bsOff);
            bsOff := bsOff + 4;
        end;
    end;

    class function TPack.bigEndianToLong(bs:TByteArray ; off:integer):int64;
    var
		  hi,lo:integer;
    begin
        hi := bigEndianToInt(bs, off);
        lo := bigEndianToInt(bs, off + 4);
        result := (int64(hi and $ffffffff) shl 32) or int64(lo and $ffffffff);
    end;

    class procedure TPack.bigEndianToLong(bs:TByteArray ; off:integer; ns:TINT64Array);
    var
       i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := bigEndianToLong(bs, off);
            off :=off + 8;
        end;
    end;

    class procedure TPack.bigEndianToLong(bs:TByteArray ; bsOff:integer; ns:TINT64Array; nsOff, nsLen:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            ns[nsOff + i] := bigEndianToLong(bs, bsOff);
            bsoff :=bsoff + 8;
        end;
    end;

    class function TPack.longToBigEndian(n:int64):TByteArray ;
    begin
        setlength(result,8);
        longToBigEndian(n, result, 0);
    end;

    class procedure TPack.longToBigEndian(n:int64; bs:TByteArray ; off:integer);
    begin
        intToBigEndian(integer(n shr 32), bs, off);
        intToBigEndian(integer(n and $ffffffff), bs, off + 4);
    end;

    class function TPack.longToBigEndian(ns:TINT64Array):TByteArray ;
    begin
        setlength(result,8 * length(ns));
        longToBigEndian(ns, result, 0);
    end;

    class procedure TPack.longToBigEndian(ns:TINT64Array; bs:TByteArray ; off:integer);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            longToBigEndian(ns[i], bs, off);
            off :=off + 8;
        end;
    end;

    class procedure TPack.longToBigEndian(ns:TINT64Array; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            longToBigEndian(ns[nsOff + i], bs, bsOff);
            bsoff :=bsoff + 8;
        end;
    end;

    {*
     * @param value The number
     * @param bs    The target.
     * @param off   Position in target to start.
     * @param bytes number of bytes to write.
     * 
     * @deprecated Will be removed
     }
    class procedure TPack.longToBigEndian( value:int64; bs:TByteArray ; off, bytes:integer);
    var
		  i:integer;
    begin
        for i := bytes - 1 downto 0 do
        begin
            bs[i + off] := byte(value and $ff);
            value :=value shr 8;
        end;
    end;

    class function TPack.littleEndianToShort(bs:TByteArray ; off:integer):int16;
    var
      n:integer;
    begin
        n := bs[off] and $ff;
				inc(off);
        n :=n or (bs[off] and $ff) shl 8;
        result := n;
    end;

    class function TPack.littleEndianToInt(bs:TByteArray ; off:integer):integer;
    var
      n:integer;
    begin
        n := bs[off] and $ff;
				inc(off);
        n :=n or (bs[off] and $ff) shl 8;
				inc(off);
        n :=n or (bs[off] and $ff) shl 16;
				inc(off);
        n :=n or  bs[off] shl 24;
        result :=  n;
    end;

    class procedure TPack.littleEndianToInt(bs:TByteArray ; off:integer; ns:TINTArray);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := littleEndianToInt(bs, off);
            Off :=Off + 4;
        end;
    end;

    class procedure TPack.littleEndianToInt(bs:TByteArray ; bOff:integer; ns:TINTArray; nOff, count:integer);
    var
		  i:integer;
    begin
        for i := 0 to count-1 do
        begin
            ns[nOff + i] := littleEndianToInt(bs, bOff);
            bOff :=bOff + 4;
        end;
    end;

    class function TPack.littleEndianToInt(bs:TByteArray ; off, count:integer):TINTArray;
    var
		  i:integer;
    begin
        setlength(result,count);
        for i := 0 to count-1 do
        begin
            result[i] := littleEndianToInt(bs, off);
            Off :=Off + 4;
        end;
    end;

    class function TPack.shortToLittleEndian(n:int16):TByteArray ;
    begin
        setlength(result,2);
        shortToLittleEndian(n, result, 0);
    end;

    class procedure TPack.shortToLittleEndian(n:int16; bs:TByteArray ; off:integer);
    begin
        bs[off] := byte(n);
				inc(off);
        bs[off] := byte(n shr 8);
    end;


    class function TPack.shortToBigEndian(n:int16):TByteArray ;
    begin
        setlength(result,2);
        shortToBigEndian(n, result, 0);
    end;

    class procedure TPack.shortToBigEndian(n:int16; bs:TByteArray ; off:integer);
    begin
        bs[off] := byte(n shr 8);
				inc(off);
        bs[off] := byte(n);
    end;


    class function TPack.intToLittleEndian(n:integer):TByteArray ;
    begin
        setlength(result,4);
        intToLittleEndian(n, result, 0);
    end;

    class procedure TPack.intToLittleEndian(n:integer; bs:TByteArray ; off:integer);
    begin
        bs[off] := byte(n);
				inc(off);
        bs[off] := byte(n shr 8);
				inc(off);
        bs[off] := byte(n shr 16);
				inc(off);
        bs[off] := byte(n shr 24);
    end;

    class function TPack.intToLittleEndian(ns:TINTArray):TByteArray ;
    begin
        setlength(result,4 * length(ns));
        intToLittleEndian(ns, result, 0);
    end;

    class procedure TPack.intToLittleEndian(ns:TINTArray; bs:TByteArray ; off:integer);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            intToLittleEndian(ns[i], bs, off);
            Off :=Off + 4;
        end;
    end;

    class procedure TPack.intToLittleEndian(ns:TINTArray; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            intToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsOff :=bsOff + 4;
        end;
    end;

    class function TPack.littleEndianToLong(bs:TByteArray ; off:integer):int64;
    var
		  lo,hi:integer;
    begin
        lo := littleEndianToInt(bs, off);
        hi := littleEndianToInt(bs, off + 4);
        result := (int64(hi and $ffffffff) shl 32) or int64(lo and $ffffffff);
    end;

    class procedure TPack.littleEndianToLong(bs:TByteArray ; off:integer; ns:TINT64Array);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            ns[i] := littleEndianToLong(bs, off);
            off :=off + 8;
        end;
    end;

    class procedure TPack.littleEndianToLong(bs:TByteArray ; bsOff:integer; ns:TINT64Array; nsOff, nsLen:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            ns[nsOff + i] := littleEndianToLong(bs, bsOff);
            bsoff :=bsoff + 8;
        end;
    end;

    class function TPack.longToLittleEndian(n:int64):TByteArray ;
    begin
        setlength(result,8);
        longToLittleEndian(n, result, 0);
    end;

    class procedure TPack.longToLittleEndian(n:int64; bs:TByteArray ; off:integer);
    begin
        intToLittleEndian(integer(n and $ffffffff), bs, off);
        intToLittleEndian(integer(n shr 32), bs, off + 4);
    end;

    class function TPack.longToLittleEndian(ns:TINT64Array):TByteArray ;
    begin
				setlength(result,8 * length(ns));
        longToLittleEndian(ns, result, 0);
    end;

    class procedure TPack.longToLittleEndian(ns:TINT64Array; bs:TByteArray ; off:integer);
    var
		  i:integer;
    begin
        for i := 0 to length(ns)-1 do
        begin
            longToLittleEndian(ns[i], bs, off);
            off :=off + 8;
        end;
    end;

    class procedure TPack.longToLittleEndian(ns:TINT64Array; nsOff, nsLen:integer; bs:TByteArray ; bsOff:integer);
    var
		  i:integer;
    begin
        for i := 0 to nsLen-1 do
        begin
            longToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsoff :=bsoff + 8;
        end;
    end;
end.
