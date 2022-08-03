Unit Primes;

interface
uses ClpBigInteger,ClpSecureRandom,ClpArrayUtils,ClpDigest,sysutils,ClpBigIntegers,math,HlpSHA2_512;
type
  TByteArray = Array of Byte;
    {
     * Used to return the output from the
     * [@linkplain Primes#enhancedMRProbablePrimeTest(TBigInteger, SecureRandom, int) Enhanced
     * Miller-Rabin Probabilistic Primality Testend;
     }
    MROutput=class
      public
        constructor create(lprovablyComposite:boolean; lfactor:TBigInteger);
        function getFactor():TBigInteger;
        function isProvablyComposite():boolean;
        function isNotPrimePower():boolean;
        class function probablyPrime():MROutput;
        class function provablyCompositeWithFactor(factor:TBigInteger ):MROutput;
        class function provablyCompositeNotPrimePower():MROutput;
      private
			  provablyComposite:boolean;
				factor:TBigInteger;
    end;
    {
     * Used to return the output from the
     * [@linkplain Primes#generateSTRandomPrime(Digest, int, byte[]) Shawe-Taylor Random_Prime
     * Routineend;
     }
    STOutput=class
		  public
        constructor create(lprime:TBigInteger; lprimeSeed:TByteArray;lprimeGenCounter:integer);
        function getPrime():TBigInteger;
        function getPrimeSeed():TByteArray;
        function getPrimeGenCounter():integer;
			
		  private
        prime:TBigInteger ;
        primeSeed:TByteArray;
        primeGenCounter:integer;
    end;
{
 * Utility methods for generating primes and testing for primality.
 }
  TPrimes=class
	  const
      SMALL_FACTOR_LIMIT: integer = 211;
    
    private
		class var 
		   ONE :TBigInteger;
       TWO :TBigInteger;
       THREE :TBigInteger;
    var
    public
		  class constructor create();
      class function generateandomPrime(bits:integer):TBigInteger;
    {
     * FIPS 186-4 C.6 Shawe-Taylor Random_Prime Routine
     *
     * Construct a provable prime number using a hash function.
     *
     * @param hash
     *            the [@link Digest]  instance to use (as 'Hash()'). Cannot be nil.
     * @param length
     *            the length (in bits) of the prime to be generated. Must be at least 2.
     * @param inputSeed
     *            the seed to be used for the generation of the requested prime. Cannot be nil or
     *            empty.
     * @return an [@link STOutput]  instance containing the requested prime.
     }
    
    class function generateSTRandomPrime(hash:TDigest; llength:integer; inputSeed:TByteArray):STOutput;

    {
     * FIPS 186-4 C.3.2 Enhanced Miller-Rabin Probabilistic Primality Test
     *
     * Run several iterations of the Miller-Rabin algorithm with randomly-chosen bases. This is an
     * alternative to [@link #isMRProbablePrime(TBigInteger, SecureRandom, int)] that provides more
     * information about a composite candidate, which may be useful when generating or validating
     * RSA moduli.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for primality.
     * @param random
     *            the source of randomness to use to choose bases.
     * @param iterations
     *            the number of randomly-chosen bases to perform the test for.
     * @return an [@link MROutput] instance that can be further queried for details.
     }
    class function enhancedMRProbablePrimeTest(candidate:TBigInteger; random:TSecureRandom; iterations:integer ):MROutput;
 
    {
     * A fast check for small divisors, up to some implementation-specific limit.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for division by small factors.
     *
     * @return <code>true</code> if the candidate is found to have any small factors,
     *         <code>false</code> otherwise.
     }
    class function hasAnySmallFactors(candidate:TBigInteger ):boolean;

    {
     * FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test
     *
     * Run several iterations of the Miller-Rabin algorithm with randomly-chosen bases.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for primality.
     * @param random
     *            the source of randomness to use to choose bases.
     * @param iterations
     *            the number of randomly-chosen bases to perform the test for.
     * @return <code>false</code> if any witness to compositeness is found amongst the chosen bases
     *         (so <code>candidate</code> is definitely NOT prime), or else <code>true</code>
     *         (indicating primality with some probability dependent on the number of iterations
     *         that were performed).
     }
    class function isMRProbablePrime(candidate:TBigInteger ; random:TSecureRandom ; iterations:integer):boolean;

    {
     * FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test (to a fixed base).
     *
     * Run a single iteration of the Miller-Rabin algorithm against the specified base.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for primality.
     * @param base
     *            the base value to use for this iteration.
     * @return <code>false</code> if the specified base is a witness to compositeness (so
     *         <code>candidate</code> is definitely NOT prime), or else <code>true</code>.
     }
    class function isMRProbablePrimeToBase(candidate:TBigInteger ; base:TBigInteger ):boolean;

    private
    class procedure checkCandidate(n:TBigInteger ; name:String );
    class function implHasAnySmallFactors(x:TBigInteger):boolean;

    class function  implMRProbablePrimeToBase( w,  wSubOne,  m:TBigInteger; a:integer;  b:TBigInteger):boolean;

    class function implSTRandomPrime(d:TDigest ;  llength:integer; primeSeed:TByteArray ):STOutput;

    class function extract32(bs:TByteArray ):integer;

    class procedure hash(d:TDigest ; input,output:TByteArray ; outPos:integer);

    class function hashGen(d:TDigest ; seed:TByteArray ; count:integer):TBigInteger;

    class procedure inc(seed:TByteArray ; c:integer);

    class function  isPrime32(x:int64):boolean;
  end;
implementation

  class function MROutput.probablyPrime():MROutput;
  begin
      result :=  MROutput.create(false, default(TBigInteger));
  end;

  class function MROutput.provablyCompositeWithFactor(factor:TBigInteger ):MROutput;
  begin
      result :=  MROutput.create(true, factor);
  end;

  class function MROutput.provablyCompositeNotPrimePower():MROutput;
  begin
      result := MROutput.create(true, default(TBigInteger));
  end;

  constructor MROutput.create(lprovablyComposite:boolean; lfactor:TBigInteger);
  begin
      provablyComposite := lprovablyComposite;
      factor := lfactor;
  end;

  function MROutput.getFactor():TBigInteger;
  begin
      result := factor;
  end;

  function MROutput.isProvablyComposite():boolean;
  begin
      result := provablyComposite;
  end;

  function MROutput.isNotPrimePower():boolean;
  var
    ti:TBigInteger;
  begin
      //result := (provablyComposite) and (factor = default(TBigInteger));
      //record version  //Terry
      ti:=default(TBigInteger);
      result := (provablyComposite) and CompareMem(@factor, @ti, SizeOf(TBigInteger));
  end;
  constructor STOutput.create(lprime:TBigInteger; lprimeSeed:TByteArray;lprimeGenCounter:integer);
  begin
    prime := lprime;
    primeSeed := lprimeSeed;
    primeGenCounter := lprimeGenCounter;
  end;

  function STOutput.getPrime():TBigInteger;
  begin
      result := prime;
  end;

  function STOutput.getPrimeSeed():TByteArray;
  begin
      result := primeSeed;
  end;

  function STOutput.getPrimeGenCounter():integer;
  begin
      result := primeGenCounter;
  end;
	class constructor TPrimes.create();
  begin
       ONE   := TBigInteger.One;
     TWO   := TBigInteger.Two;
     THREE := TBigInteger.Three;
	end;
	class function TPrimes.generateandomPrime(bits:integer):TBigInteger;
	  const
		  seedsize=32;
	var
	   i:integer;
     digest:TDigest;
     seeds:TByteArray;
     ahash:TSHA2_512;
	begin
    randomize;
    ahash:=TSHA2_512.Create();
    digest:=TDigest.create(ahash);
    setlength(seeds,seedsize);
    for i:=0 to seedsize-1 do
    begin
       seeds[i]:=Random(255);
    end;
    
		{setlength(seeds,2);
    seeds[0]:=12;
		seeds[1]:=32;
		}
    result:=generateSTRandomPrime(digest,bits,seeds).getPrime();
	end;
    class function TPrimes.generateSTRandomPrime(hash:TDigest; llength:integer; inputSeed:TByteArray):STOutput;
    var
       newinputseed:TByteArray;
    begin
        if (hash = nil) then
        begin
            Raise  exception.create('"hash" cannot be nil');
        end;
        if (llength < 2) then
        begin
            Raise  exception.create('"length" must be >= 2');
        end;
        if (inputSeed = nil) or (length(inputSeed) = 0) then
        begin
            Raise  exception.create('"inputSeed" cannot be nil or empty');
        end;
        setlength(newinputseed,length(inputSeed));
        move(inputSeed[0],newinputseed[0],length(inputSeed));
        result := implSTRandomPrime(hash, llength, newinputseed);
    end;

    {
     * FIPS 186-4 C.3.2 Enhanced Miller-Rabin Probabilistic Primality Test
     *
     * Run several iterations of the Miller-Rabin algorithm with randomly-chosen bases. This is an
     * alternative to [@link #isMRProbablePrime(TBigInteger, SecureRandom, int)] that provides more
     * information about a composite candidate, which may be useful when generating or validating
     * RSA moduli.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for primality.
     * @param random
     *            the source of randomness to use to choose bases.
     * @param iterations
     *            the number of randomly-chosen bases to perform the test for.
     * @return an [@link MROutput] instance that can be further queried for details.
     }
    class function TPrimes.enhancedMRProbablePrimeTest(candidate:TBigInteger; random:TSecureRandom; iterations:integer ):MROutput;
    var
		  b,g,w,m,z,x,wSubOne,wSubTwo:TBigInteger;
			a,i,j:integer;
			primeToBase:boolean;
    begin
        checkCandidate(candidate, 'candidate');

        if (random = nil) then
        begin
            Raise  exception.create('"random" cannot be nil');
        end;
        if (iterations < 1) then
        begin
            Raise  exception.create('"iterations" must be > 0');
        end;

        if (candidate.bitLength = 2) then
        begin
            exit(MROutput.probablyPrime());
        end;
        if (not candidate.testBit(0)) then
        begin
            exit(MROutput.provablyCompositeWithFactor(TWO));
        end;

        w := candidate;
        wSubOne := candidate.subtract(ONE);
        wSubTwo := candidate.subtract(TWO);

        a := wSubOne.getLowestSetBit();
        m := wSubOne.shiftRight(a);

        for i := 0 to iterations-1 do
        begin
            b := TBigIntegers.createRandomInRange(TWO, wSubTwo, random);
            g := b.gcd(w);

            if (g.compareTo(ONE) > 0) then
            begin
                exit(MROutput.provablyCompositeWithFactor(g));
            end;

            z := b.&modPow(m, w);

            if (z.equals(ONE)) or (z.equals(wSubOne)) then
            begin
                continue;
            end;

            primeToBase := false;

            x := z;
            for j := 1 to a-1 do
            begin
                z := z.&modPow(TWO, w);

                if (z.equals(wSubOne)) then
                begin
                    primeToBase := true;
                    break;
                end;

                if (z.equals(ONE)) then
                begin
                    break;
                end;

                x := z;
            end;

            if (not primeToBase) then
            begin
                if (not z.equals(ONE)) then
                begin
                    x := z;
                    z := z.&modPow(TWO, w);

                    if (not z.equals(ONE)) then
                    begin
                        x := z;
                    end;
                end;

                g := x.subtract(ONE).gcd(w);

                if (g.compareTo(ONE) > 0) then
                begin
                    exit(MROutput.provablyCompositeWithFactor(g));
                end;

                exit(MROutput.provablyCompositeNotPrimePower())
            end;
        end;

        exit (MROutput.probablyPrime());
    end;

    {
     * A fast check for small divisors, up to some implementation-specific limit.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for division by small factors.
     *
     * @return <code>true</code> if the candidate is found to have any small factors,
     *         <code>false</code> otherwise.
     }
    class function TPrimes.hasAnySmallFactors(candidate:TBigInteger ):boolean;
    begin
        checkCandidate(candidate, 'candidate');

        exit(implHasAnySmallFactors(candidate));
    end;

    {
     * FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test
     *
     * Run several iterations of the Miller-Rabin algorithm with randomly-chosen bases.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for primality.
     * @param random
     *            the source of randomness to use to choose bases.
     * @param iterations
     *            the number of randomly-chosen bases to perform the test for.
     * @return <code>false</code> if any witness to compositeness is found amongst the chosen bases
     *         (so <code>candidate</code> is definitely NOT prime), or else <code>true</code>
     *         (indicating primality with some probability dependent on the number of iterations
     *         that were performed).
     }
    class function TPrimes.isMRProbablePrime(candidate:TBigInteger ; random:TSecureRandom ; iterations:integer):boolean;
    var
		  b,g,w,m,z,x,wSubOne,wSubTwo:TBigInteger;
			a,i,j:integer;
			primeToBase:boolean;
    begin
        checkCandidate(candidate, 'candidate');

        if (random = nil) then
        begin
            Raise  exception.create('"random" cannot be nil');
        end;
        if (iterations < 1) then
        begin
            Raise  exception.create('"iterations" must be > 0');
        end;

        if (candidate.bitLength = 2) then
        begin
            exit(true);
        end;
        if (not candidate.testBit(0)) then
        begin
            exit(false);
        end;

        w := candidate;
        wSubOne := candidate.subtract(ONE);
        wSubTwo := candidate.subtract(TWO);

        a := wSubOne.getLowestSetBit();
        m := wSubOne.shiftRight(a);

        for i := 0 to iterations-1 do
        begin
            b := TBigIntegers.createRandomInRange(TWO, wSubTwo, random);

            if (not implMRProbablePrimeToBase(w, wSubOne, m, a, b)) then
            begin
                exit(false);
            end;
        end;

        result :=true;
    end;

    {
     * FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test (to a fixed base).
     *
     * Run a single iteration of the Miller-Rabin algorithm against the specified base.
     *
     * @param candidate
     *            the [@link TBigInteger] instance to test for primality.
     * @param base
     *            the base value to use for this iteration.
     * @return <code>false</code> if the specified base is a witness to compositeness (so
     *         <code>candidate</code> is definitely NOT prime), or else <code>true</code>.
     }
    class function TPrimes.isMRProbablePrimeToBase(candidate:TBigInteger ; base:TBigInteger ):boolean;
    var
		  m, w,wSubOne:TBigInteger;
			a:integer;
    begin
        checkCandidate(candidate, 'candidate');
        checkCandidate(base, 'base');

        if (base.compareTo(candidate.subtract(ONE)) >= 0) then
        begin
            Raise  exception.create('"base" must be < ("candidate" - 1)');
        end;

        if (candidate.bitLength = 2) then
        begin
            exit(true);
        end;

        w := candidate;
        wSubOne := candidate.subtract(ONE);

        a := wSubOne.getLowestSetBit();
        m := wSubOne.shiftRight(a);

        result := implMRProbablePrimeToBase(w, wSubOne, m, a, base);
    end;

    class procedure TPrimes.checkCandidate(n:TBigInteger ; name:String );
    var
       ti:TBigInteger;
    begin
        //if (n = nil) or (n.SignValue  < 1) or (n.bitLength < 2) then
        //record version //Terry
        ti:=default(TBigInteger);
        if (CompareMem(@n, @ti, SizeOf(TBigInteger))) or (n.SignValue  < 1) or (n.bitLength < 2) then
        begin
            Raise  exception.create('"' + name + '" must be non-nil and >= 2');
        end;
    end;

    class function TPrimes.implHasAnySmallFactors(x:TBigInteger):boolean;
    var
		  m,r:integer;
    begin
        {
         * Bundle trial divisors into ~32-bit moduli then use fast tests on the ~32-bit remainders.
         }
        m := 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23;
        r := x.&mod(TBigInteger.valueOf(m)).Int32Value;
        if ((r mod 2) = 0) or ((r mod 3) = 0) or ((r mod 5) = 0) or ((r mod 7) = 0) or ((r mod 11) = 0) or ((r mod 13) = 0)
            or ((r mod 17) = 0) or ((r mod 19) = 0) or ((r mod 23) = 0) then
        begin
            exit(true);
        end;

        m := 29 * 31 * 37 * 41 * 43;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 29) = 0) or ((r mod 31) = 0) or ((r mod 37) = 0) or ((r mod 41) = 0) or ((r mod 43) = 0) then
        begin
            exit(true);
        end;

        m := 47 * 53 * 59 * 61 * 67;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 47) = 0) or ((r mod 53) = 0) or ((r mod 59) = 0) or ((r mod 61) = 0) or ((r mod 67) = 0) then
        begin
            exit(true);
        end;

        m := 71 * 73 * 79 * 83;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 71) = 0) or ((r mod 73) = 0) or ((r mod 79) = 0) or ((r mod 83) = 0) then
        begin
            exit(true);
        end;

        m := 89 * 97 * 101 * 103;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 89) = 0) or ((r mod 97) = 0) or ((r mod 101) = 0) or ((r mod 103) = 0) then
        begin
            exit(true);
        end;

        m := 107 * 109 * 113 * 127;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 107) = 0) or ((r mod 109) = 0) or ((r mod 113) = 0) or ((r mod 127) = 0) then
        begin
            exit(true);
        end;

        m := 131 * 137 * 139 * 149;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 131) = 0) or ((r mod 137) = 0) or ((r mod 139) = 0) or ((r mod 149) = 0) then
        begin
            exit(true);
        end;

        m := 151 * 157 * 163 * 167;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 151) = 0) or ((r mod 157) = 0) or ((r mod 163) = 0) or ((r mod 167) = 0) then
        begin
            exit(true);
        end;

        m := 173 * 179 * 181 * 191;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 173) = 0) or ((r mod 179) = 0) or ((r mod 181) = 0) or ((r mod 191) = 0) then
        begin
            exit(true);
        end;

        m := 193 * 197 * 199 * 211;
        r := x.&mod(TBigInteger.valueOf(m)).int32Value;
        if ((r mod 193) = 0) or ((r mod 197) = 0) or ((r mod 199) = 0) or ((r mod 211) = 0) then
        begin
            exit(true);
        end;

        {
         * NOTE: Unit tests depend on SMALL_FACTOR_LIMIT matching the
         * highest small factor tested here.
         }
        exit(false);
    end;

    class function  TPrimes.implMRProbablePrimeToBase( w,  wSubOne,  m:TBigInteger; a:integer;  b:TBigInteger):boolean;
    var
		  z:TBigInteger;
			j:integer;
    begin
        z := b.&modPow(m, w);

        if (z.equals(ONE)) or (z.equals(wSubOne)) then
        begin
            exit(true);
        end;

        result := false;

        for j := 1 to a-1 do
        begin
            z := z.&modPow(TWO, w);

            if (z.equals(wSubOne)) then
            begin
                result := true;
                break;
            end;

            if (z.equals(ONE)) then
            begin
                exit(false);
            end;
        end;
    end;

    class function TPrimes.implSTRandomPrime(d:TDigest ;  llength:integer; primeSeed:TByteArray ):STOutput;
    var
		  dLen,primeGenCounter,ca:integer;
			c0a,c1a:TByteArray;
			c64:int64;
			rec:STOutput;
      a,c0,x,c0x2,tx2,c,z,tmp:TBigInteger;
      outlen,iterations,oldCounter,dt:integer;
    begin
        dLen := d.GetDigestSize;
        //writeln(stdout,'dLen=',dLen);
        if (llength < 33) then
        begin
            primeGenCounter := 0;

            setlength(c0a,dLen);
            setlength(c1a,dLen);

            while true do
            begin
                hash(d, primeSeed, c0a, 0);
                inc(primeSeed, 1);

                hash(d, primeSeed, c1a, 0);
                inc(primeSeed, 1);

                ca := extract32(c0a) xor extract32(c1a);
								//writeln(stdout,'c=',ca);
                ca :=ca and uint32(uint32($FFFFFFFFFFFFFFFF) shr (32 - llength));
								//writeln(stdout,'c1=',ca);
                ca :=ca or (1 shl (llength - 1)) or 1;
								//writeln(stdout,'c2=',ca);

                primeGenCounter:=primeGenCounter+1;
                //writeln(stdout,'primeGenCounter=',primeGenCounter);
                c64 := ca and $FFFFFFFF;
								//writeln(stdout,'c64=',c64);
                if (isPrime32(c64)) then
                begin
                    exit(STOutput.create(TBigInteger.valueOf(c64), primeSeed, primeGenCounter));
                end;

                if (primeGenCounter > (4 * llength))  then
                begin
                    Raise  exception.create('Too many iterations in Shawe-Taylor Random_Prime Routine');
                end;
            end;
        end;

        rec := implSTRandomPrime(d, (llength + 3) div 2, primeSeed);

        c0 := rec.getPrime();
        primeSeed := rec.getPrimeSeed();
        primeGenCounter := rec.getPrimeGenCounter();
        //writeln(stdout,'primeGenCounter2=',primeGenCounter);
        outlen := 8 * dLen;
				//writeln(stdout,'outlen=',outlen);
        iterations := (llength - 1) div outlen;
        //writeln(stdout,'iterations=',iterations);
        oldCounter := primeGenCounter;
        //writeln(stdout,'oldCounter=',oldCounter);
        x := hashGen(d, primeSeed, iterations + 1);
				tmp := ONE.shiftLeft(llength - 1);
				//writeln(stdout,'=ONE shiftLeft=',(llength - 1));
				//writeln(stdout,'=ONE=',tmp.ToString);
        x := x.&mod(ONE.shiftLeft(llength - 1)).setBit(llength - 1);

        c0x2 := c0.shiftLeft(1);
        tx2 := x.subtract(ONE).divide(c0x2).add(ONE).shiftLeft(1);
        dt := 0;

        c := tx2.multiply(c0).add(ONE);

        {
         * TODO Since the candidate primes are generated by constant steps ('c0x2'), sieving could
         * be used here in place of the 'hasAnySmallFactors' approach.
         }
        while true do
        begin
            if (c.bitLength > llength) then
            begin
                tx2 := ONE.shiftLeft(llength - 1).subtract(ONE).divide(c0x2).add(ONE).shiftLeft(1);
                c := tx2.multiply(c0).add(ONE);
            end;

            primeGenCounter:=primeGenCounter+1;
            //writeln(stdout,'primeGenCounter3=',primeGenCounter);
            {
             * This is an optimization of the original algorithm, using trial division to screen out
             * many non-primes quickly.
             * 
             * NOTE: 'primeSeed' is still incremented as if we performed the full checknot 
             }
            if (not implHasAnySmallFactors(c)) then
            begin
                a := hashGen(d, primeSeed, iterations + 1);
                a := a.&mod(c.subtract(THREE)).add(TWO);

                tx2 := tx2.add(TBigInteger.valueOf(dt));
                dt := 0;

                z := a.&modPow(tx2, c);

                if (c.gcd(z.subtract(ONE)).equals(ONE)) and (z.&modPow(c0, c).equals(ONE)) then
                begin
                    exit (STOutput.create(c, primeSeed, primeGenCounter));
                end;
            end
            else
            begin
                inc(primeSeed, iterations + 1);
            end;

            if (primeGenCounter >= ((4 * llength) + oldCounter)) then
            begin
                Raise  exception.create('Too many iterations in Shawe-Taylor Random_Prime Routine');
            end;

            dt :=dt + 2;
						//writeln(stdout,'dt=',dt);
            c := c.add(c0x2);
        end;
    end;

    class function TPrimes.extract32(bs:TByteArray ):integer;
    var
		  count,i,b:integer;
    begin
      result := 0;

      count := min(4, length(bs));
      for i := 0 to count-1 do
      begin
          b := bs[length(bs) - (i + 1)] and $FF;
          result :=result or (b shl (8 * i));
      end;
			//writeln(stdout,'extract32=',result);
    end;

    class procedure TPrimes.hash(d:TDigest ; input,output:TByteArray ; outPos:integer);
    begin
        d.BlockUpdate(input, 0, length(input));
        d.doFinal(output, outPos);
    end;

    class function TPrimes.hashGen(d:TDigest ; seed:TByteArray ; count:integer):TBigInteger;
    var
		  dLen,pos,i:integer;
			buf:TByteArray ;
    begin
        dLen := d.geTDigestSize();
        pos := count * dLen;
        setlength(buf,pos);
        for i := 0 to count-1 do
        begin
            pos :=pos - dLen;
            hash(d, seed, buf, pos);
            inc(seed, 1);
        end;
        result := TBigInteger.create(1, buf);
    end;

    class procedure TPrimes.inc(seed:TByteArray ; c:integer);
    var
		  pos:integer;
    begin
        pos := length(seed);
				dec(pos);
        while (c > 0) and (pos >= 0) do
        begin
            c :=c + (seed[pos] and $FF);
            seed[pos] := byte(c);
            c :=c shr 8;
        end;
    end;

    class function TPrimes.isPrime32(x:int64):boolean;
    var
		  ds:array[0..7] of int64=(1, 7, 11, 13, 17, 19, 23, 29);
			base,d:int64;
			pos:integer;
    begin
        if (x shr 32 <> 0) then
        begin
            Raise  exception.create('Size limit exceeded');
        end;

        {
         * Use wheel factorization with 2, 3, 5 to select trial divisors.
         }

        if (x <= 5) then
        begin
            exit((x = 2) or (x = 3) or (x = 5));
        end;

        if ((x and 1) = 0) or ((x mod 3) = 0) or ((x mod 5) = 0) then
        begin
            exit(false);
        end;

        base := 0;
				pos := 1;
        while true do
        begin
            {
             * Trial division by wheel-selected divisors
             }
            while (pos < length(ds)) do
            begin
                d := base + ds[pos];
                if (x mod d = 0) then
                begin
                    exit(x < 30);
                end;
                pos:=pos+1;
            end;

            base :=base + 30;

            if (base * base >= x) then
            begin
                exit(true);
            end;
						pos := 0;
        end;
    end;
end.
