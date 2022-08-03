unit ClpMod;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
{$IFDEF DELPHI}
  ClpBitConverter,
{$ENDIF DELPHI}
  ClpNat,
  ClpConverters,Sysutils,
  ClpSecureRandom,Math,
  ClpISecureRandom;

resourcestring
  SCannotBeZero = 'cannot be 0, "x"';
  const
    M30:integer = $3FFFFFFF;
    M32L:int64 =  $FFFFFFFF;
type

  TMod = class abstract(TObject)

  strict private

    class var

      FRandomSource: ISecureRandom;

    class procedure Boot(); static;
    class constructor andMod();

    class procedure InversionResult(const p: TCryptoLibUInt32Array; ac: Int32;
      const a: TCryptoLibUInt32Array; const z: TCryptoLibUInt32Array);
      static; inline;
    class procedure InversionStep(const p, u: TCryptoLibUInt32Array;
      uLen: Int32; const x: TCryptoLibUInt32Array; var xc: Int32); static;
    class function divsteps30(eta, f0, g0:integer;t:TCryptoLibUInt32Array):integer; static;
    class function getMaximumDivsteps(bits:integer):integer;  static;
    class function inverse32(d:integer):integer; static;
    class procedure cnegate30( len30,  cond:integer; D:TCryptoLibUInt32Array); static;
    class procedure decode30(bits:integer; x:TCryptoLibUInt32Array; xOff:integer; z:TCryptoLibUInt32Array; zOff:integer); static;
    class procedure cnormalize30(len30, condNegate:integer;D, M:TCryptoLibUInt32Array); static;
    class procedure updateFG30(len30:integer; F, G, t:TCryptoLibUInt32Array);  static;
    class procedure updateDE30(len30:integer; D, E, t:TCryptoLibUInt32Array; m0Inv32:integer; M:TCryptoLibUInt32Array); static;
    class procedure encode30(bits:integer; x:TCryptoLibUInt32Array; xOff:integer;z:TCryptoLibUInt32Array; zOff:integer); static;
  public
    class procedure Invert(const p, x, z: TCryptoLibUInt32Array); static;
    class function Random(const p: TCryptoLibUInt32Array)
      : TCryptoLibUInt32Array; static;
    class procedure Add(const p, x, y, z: TCryptoLibUInt32Array);
      static; inline;
    class procedure Subtract(const p, x, y, z: TCryptoLibUInt32Array);
      static; inline;
    class function GetTrailingZeroes(x: UInt32): Int32; static; inline;
    class function modOddInverse(lm, lx, lz:TCryptoLibUInt32Array):integer;static;
    class procedure checkedModOddInverse(lm, lx, lz:TCryptoLibUInt32Array);
  end;

implementation

{TMod}

class procedure TMod.Add(const p, x, y, z: TCryptoLibUInt32Array);
var
  len: Int32;
  c: UInt32;
begin
  len := System.Length(p);
  c := TNat.Add(len, x, y, z);
  if (c <> 0) then
  begin
    TNat.SubFrom(len, p, z);
  end;
end;

class procedure TMod.Boot;
begin

  FRandomSource := TSecureRandom.Create();
end;

class function TMod.GetTrailingZeroes(x: UInt32): Int32;
var
  count: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(x <> 0);
{$ENDIF DEBUG}
  count := 0;
  while ((x and 1) = 0) do
  begin
    x := x shr 1;
    System.Inc(count);
  end;
  result := count;
end;

class procedure TMod.InversionResult(const p: TCryptoLibUInt32Array; ac: Int32;
  const a, z: TCryptoLibUInt32Array);
begin
  if (ac < 0) then
  begin
    TNat.Add(System.Length(p), a, p, z);
  end
  else
  begin
    System.Move(a[0], z[0], System.Length(p) * System.SizeOf(UInt32));
  end;
end;

class procedure TMod.InversionStep(const p, u: TCryptoLibUInt32Array;
  uLen: Int32; const x: TCryptoLibUInt32Array; var xc: Int32);
var
  len, count, zeroes, i: Int32;
begin
  len := System.Length(p);
  count := 0;
  while (u[0] = 0) do
  begin
    TNat.ShiftDownWord(uLen, u, 0);
    count := count + 32;
  end;

  zeroes := GetTrailingZeroes(u[0]);
  if (zeroes > 0) then
  begin
    TNat.ShiftDownBits(uLen, u, zeroes, 0);
    count := count + zeroes;
  end;

  i := 0;
  while i < count do
  begin

    if ((x[0] and 1) <> 0) then
    begin
      if (xc < 0) then
      begin
        xc := xc + Int32(TNat.AddTo(len, p, x));
      end
      else
      begin
        xc := xc + (TNat.SubFrom(len, p, x));
      end;
    end;

    TNat.ShiftDownBit(len, x, UInt32(xc));

    System.Inc(i);
  end;

end;

class procedure TMod.Invert(const p, x, z: TCryptoLibUInt32Array);
var
  len, ac, bc, uvLen: Int32;
  u, a, v, b: TCryptoLibUInt32Array;
begin
  len := System.Length(p);
  if (TNat.IsZero(len, x)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeZero);
  end;
  if (TNat.IsOne(len, x)) then
  begin
    System.Move(x[0], z[0], len * System.SizeOf(UInt32));
    Exit;
  end;

  u := TNat.Copy(len, x);
  a := TNat.Create(len);
  a[0] := 1;
  ac := 0;

  if ((u[0] and 1) = 0) then
  begin
    InversionStep(p, u, len, a, ac);
  end;

  if (TNat.IsOne(len, u)) then
  begin
    InversionResult(p, ac, a, z);
    Exit;
  end;

  v := TNat.Copy(len, p);
  b := TNat.Create(len);
  bc := 0;

  uvLen := len;

  while True do

  begin
    while ((u[uvLen - 1] = 0) and (v[uvLen - 1] = 0)) do
    begin
      System.Dec(uvLen);
    end;

    if (TNat.Gte(len, u, v)) then
    begin
      TNat.SubFrom(len, v, u);
      ac := ac + (TNat.SubFrom(len, b, a) - bc);
      InversionStep(p, u, uvLen, a, ac);
      if (TNat.IsOne(len, u)) then
      begin
        InversionResult(p, ac, a, z);
        Exit;
      end;
    end
    else
    begin
      TNat.SubFrom(len, u, v);
      bc := bc + (TNat.SubFrom(len, a, b) - ac);
      InversionStep(p, v, uvLen, b, bc);
      if (TNat.IsOne(len, v)) then
      begin
        InversionResult(p, bc, b, z);
        Exit;
      end;
    end;
  end;
end;

class constructor TMod.andMod;
begin
  TMod.Boot;
end;

class function TMod.Random(const p: TCryptoLibUInt32Array)
  : TCryptoLibUInt32Array;
var
  len: Int32;
  m: UInt32;
  s: TCryptoLibUInt32Array;
  bytes: TCryptoLibByteArray;
begin
  len := System.Length(p);
  s := TNat.Create(len);

  m := p[len - 1];
  m := m or (m shr 1);
  m := m or (m shr 2);
  m := m or (m shr 4);
  m := m or (m shr 8);
  m := m or (m shr 16);

  System.SetLength(bytes, len shl 2);

  repeat
    FRandomSource.NextBytes(bytes);
    TConverters.be32_copy(PByte(bytes), 0, PCardinal(s), 0, System.Length(s));
    s[len - 1] := s[len - 1] and m;

  until (not(TNat.Gte(len, s, p)));

  result := s;
end;

class procedure TMod.Subtract(const p, x, y, z: TCryptoLibUInt32Array);
var
  len, c: Int32;
begin
  len := System.Length(p);
  c := TNat.Sub(len, x, y, z);
  if (c <> 0) then
  begin
    TNat.AddTo(len, p, z);
  end;
end;

  class function numberOfLeadingZeros(i:integer): integer;
  var
    n:integer;
  begin
  	// HD, Count leading 0's
    if (i <= 0) then
    begin
      //负数，首位就是1，所以返回0；如果正好是0，那么返回32
      if i=0 then
        exit(32)
      else
        exit(0);                                                                   
    end;
  	n := 31;
	
  	//如果高16位有1，那么n减半（二分查找的核心），i无符号右移16位，保留高16位
  	if (i >= 1 shl 16) then
  	begin
  	   n :=n - 16; 
  	   i :=i shr 16;
  	end;
  	//到这里，如果前面一步没有截断，那么高16位都是0；如果上面一步截断了，那么只有16位了。
  	//如果高8位有1，那么n减半（二分查找的核心），i无符号右移16位，保留高16位
  	if (i >= 1 shl  8) then 
  	begin 
  	  n :=n -  8; 
  	  i :=i shr  8;
  	end;
  	//与上面同理。都是二分查找
  	if (i >= 1 shl  4) then 
  	begin
  	   n :=n -  4; 
  	   i :=i shr 4; 
    end;
  	if (i >= 1 shl  2) then 
  	begin
  	   n :=n -  2; 
  	   i :=i shr  2; 
  	end;
  	//最终返回结果
  	result := n - (i shr 1);
  end;
    class procedure TMod.encode30(bits:integer; x:TCryptoLibUInt32Array; xOff:integer;z:TCryptoLibUInt32Array; zOff:integer);
    var
      avail:integer;
      data:int64;
    begin
        avail := 0;
        data  := 0;

        while (bits > 0) do
        begin
            if (avail < min(30, bits)) then
            begin
                data :=data or (x[xOff] and M32L) shl avail;
                inc(xOff);
                avail :=avail + 32;
            end;

            z[zOff] := integer(data) and M30;
            inc(xOff); 
            data :=data shr 30;
            avail :=avail- 30;
            bits :=bits - 30;
        end;
    end;
    class procedure TMod.updateDE30(len30:integer; D, E, t:TCryptoLibUInt32Array; m0Inv32:integer; M:TCryptoLibUInt32Array);
    var
      u,v,q,r:integer;
      di, ei, i, md, me, mi, sd, se:integer;
      cd,ce:int64;
    begin
        u := t[0];
        v := t[1];
        q := t[2];
        r := t[3];
        {
         * We accept D (E) in the range (-2.M, M) and conceptually add the modulus to the input
         * value if it is initially negative. Instead of adding it explicitly, we add u and/or v (q
         * and/or r) to md (me).
         }
        sd := SarLongint(D[len30 - 1] , 31);
        se := SarLongint(E[len30 - 1] , 31);

        md := (u and sd) + (v and se);
        me := (q and sd) + (r and se);

        mi := M[0];
        di := D[0];
        ei := E[0];

        cd := int64(u) * di + int64(v) * ei;
        ce := int64(q) * di + int64(r) * ei;

        {
         * Subtract from md/me an extra term in the range [0, 2xor30) such that the low 30 bits of the
         * intermediate D/E values will be 0, allowing clean division by 2xor30. The final D/E are
         * thus in the range (-2.M, M), consistent with the input constraint.
         }
        md :=md - (m0Inv32 * integer(cd) + md) and M30;
        me :=me - (m0Inv32 * integer(ce) + me) and M30;

        cd :=cd + int64(mi) * md;
        ce :=ce + int64(mi) * me;

//        assert ((int)cd and M30) == 0;
//        assert ((int)ce and M30) == 0;

        cd :=SarLongint(cd , 30);
        ce :=SarLongint(ce , 30);

        for i := 1 to len30-1 do
        begin
            mi := M[i];
            di := D[i];
            ei := E[i];

            cd :=cd + int64(u) * di + int64(v) * ei + int64(mi) * md;
            ce :=ce + int64(q) * di + int64(r) * ei + int64(mi) * me;

            D[i - 1] := integer(cd) and M30; 
            cd :=SarLongint(cd , 30);
            E[i - 1] := integer(ce) and M30; 
            ce :=SarLongint(ce , 30);
        end;

        D[len30 - 1] := integer(cd);
        E[len30 - 1] := integer(ce);
    end;

    class procedure TMod.updateFG30(len30:integer; F, G, t:TCryptoLibUInt32Array);
    var
      u,v,q,r:integer;
      fi,gi,i:integer;
      cf,cg:int64;
    begin
        u := t[0];
        v := t[1];
        q := t[2];
        r := t[3];

        fi := F[0];
        gi := G[0];

        cf := int64(u) * fi + int64(v) * gi;
        cg := int64(q) * fi + int64(r) * gi;


        cf :=SarLongint(cf , 30);
        cg :=SarLongint(cg , 30);

        for i := 1 to len30-1 do
        begin
            fi := F[i];
            gi := G[i];

            cf :=cf + int64(u) * fi + int64(v) * gi;
            cg :=cg + int64(q) * fi + int64(r) * gi;

            F[i - 1] := integer(cf) and M30; 
            cf :=SarLongint(cf , 30);
            G[i - 1] := integer(cg) and M30; 
            cg :=SarLongint(cg , 30);
        end;

        F[len30 - 1] := integer(cf);
        G[len30 - 1] := integer(cg);
    end;
    class procedure TMod.cnormalize30(len30, condNegate:integer;D, M:TCryptoLibUInt32Array);
    var
      last,c,condAdd,i,di:integer;
    begin

        last := len30 - 1;

        c := 0;
        condAdd := SarLongint(D[last] , 31);
        for i := 0 to last -1 do
        begin
            di := D[i] + (M[i] and condAdd);
            di := (di xor condNegate) - condNegate;
            c  :=c + di; 
            D[i] := c and M30; 
            c :=SarLongint(c , 30);
        end;
        di := D[last] + (M[last] and condAdd);
        di := (di xor condNegate) - condNegate;
        c :=c + di; 
        D[last] := c;

        c := 0;
        condAdd := SarLongint(D[last] , 31);
        for i := 0 to last -1 do
        begin
            di := D[i] + (M[i] and condAdd);
            c  :=c + di; 
            D[i] := c and M30; 
            c :=SarLongint(c , 30);
        end;
        di := D[last] + (M[last] and condAdd);
        c :=c + di; 
        D[last] := c;
    end;

    class procedure TMod.decode30(bits:integer; x:TCryptoLibUInt32Array; xOff:integer; z:TCryptoLibUInt32Array; zOff:integer);
      var
        avail:integer;
        data:int64;
    begin

        avail := 0;
        data  := 0;

        while (bits > 0) do
        begin
            while (avail < min(32, bits)) do
            begin
                data :=data or int64(x[xOff]) shl avail;
                inc(xOff);
                avail :=avail + 30;
            end;

            z[zOff] := Integer(data);
            data :=data shr 32;
            inc(xOff);
            avail :=avail - 32;
            bits :=bits - 32;
        end;
    end;
    class procedure TMod.cnegate30( len30,  cond:integer; D:TCryptoLibUInt32Array);
      var
        c,last,i:integer;
    begin
        c := 0; 
        last := len30 - 1;
        for i := 0 to last -1 do
        begin
            c :=c + (D[i] xor cond) - cond;
            D[i] := c and M30; 
            c :=SarLongint(c , 30);
        end;
        c :=c + (D[last] xor cond) - cond;
        D[last] := c;
    end;
    class function TMod.inverse32(d:integer):integer;
    begin
        result := d;                          // d.x == 1 mod 2**3
        result :=result * 2 - d * result;                     // d.x == 1 mod 2**6
        result :=result * 2 - d * result;                     // d.x == 1 mod 2**12
        result :=result * 2 - d * result;                     // d.x == 1 mod 2**24
        result :=result * 2 - d * result;                     // d.x == 1 mod 2**48
    end;
    class function TMod.getMaximumDivsteps(bits:integer):integer;
    begin
      if bits < 46 then
        result := (49 * bits + 80 ) div 17
      else
        result := (49 * bits + 47) div 17;
    end;
    class function TMod.divsteps30(eta, f0, g0:integer;t:TCryptoLibUInt32Array):integer;
    var
      u,v,q,r,f,g,i:integer;
      c1,c2,x,y,z:integer;
    begin
        u := 1;
        v := 0;
        q := 0;
        r := 1;
        f := f0;
        g := g0;

        for i := 0 to 29 do
        begin
            c1 := SarLongint(eta , 31);
            c2 := -(g and 1);

            x := (f xor c1) - c1;
            y := (u xor c1) - c1;
            z := (v xor c1) - c1;

            g :=g + x and c2;
            q :=q + y and c2;
            r :=r + z and c2;

            c1 :=c1 and c2;
            eta := (eta xor c1) - (c1 + 1);

            f :=f + g and c1;
            u :=u + q and c1;
            v :=v + r and c1;

            g :=SarLongint(g , 1);
            u :=u shl 1;
            v :=v shl 1;
        end;

        t[0] := u;
        t[1] := v;
        t[2] := q;
        t[3] := r;

        result := eta;
   end;
   class function TMod.modOddInverse(lm, lx, lz:TCryptoLibUInt32Array):integer;
   var
     len32,bits,len30,eta,m0Inv32,maxDivsteps,divSteps,signF:integer;
     t,D,E,F,G,M:TCryptoLibUInt32Array;
   begin
        len32 := length(lm);

        bits  := (len32 shl 5) - numberOfLeadingZeros(m[len32 - 1]);
        len30 := (bits + 29) div 30;

        setlength(t,4);
        setlength(D,len30);
        setlength(E,len30);
        setlength(F,len30);
        setlength(G,len30);
        setlength(M,len30);

        E[0] := 1;
        encode30(bits, lx, 0, G, 0);
        encode30(bits, lm, 0, M, 0);
        move(M[0], F[0], len30);

        eta := -1;
        m0Inv32     := inverse32(M[0]);
        maxDivsteps := getMaximumDivsteps(bits);
        divSteps := 0;
        while divSteps < maxDivsteps do 
        begin
            eta := divsteps30(eta, F[0], G[0], t);
            updateDE30(len30, D, E, t, m0Inv32, M);
            updateFG30(len30, F, G, t);
            divSteps :=divSteps + 30;
        end;

        signF := F[len30 - 1] shr 31;
        cnegate30(len30, signF, F);

        {
         * D is in the range (-2.M, M). First, conditionally add M if D is negative, to bring it
         * into the range (-M, M). Then normalize by conditionally negating (according to signF)
         * and/or then adding M, to bring it into the range [0, M).
         }
        cnormalize30(len30, signF, D, M);

        decode30(bits, D, 0, lz, 0);

        result := TNat.equalTo(len30, F, 1) and TNat.equalToZero(len30, G);
   end;
   class procedure TMod.checkedModOddInverse(lm, lx, lz:TCryptoLibUInt32Array);
   begin
       if (0 = modOddInverse(lm, lx, lz)) then
       begin
           Raise Exception.create('Inverse does not exist.');
       end;
   end;
end.
