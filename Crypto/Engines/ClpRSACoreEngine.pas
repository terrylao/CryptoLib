unit ClpRSACoreEngine;
interface

uses clpBigInteger,ClpRSAKeyParameters,ClpRSAPrivateCrtKeyParameters,sysutils,
  ClpICipherParameters,ClpIAsymmetricBlockCipher,ClpSecureRandom;

Type
{*
 * this does your basic RSA algorithm.
 *}
  TRSACoreEngine=class //sealed(TInterfacedObject,IAsymmetricBlockCipher)
    private
      key:TRSAKeyParameters;
      forEncryption:boolean;
      //random:TSecureRandom;
      class var ONE:TBigInteger;
      class procedure boot();
    public
      function processBlock(inbuf:Tbytes;inOff,inLen:integer):Tbytes;
      function  processBlock(input:TBigInteger):TBigInteger;
      function convertOutput(r:TBigInteger):TBytes;
      function  convertInput(inbuf:TBytes;inOff,inLen:integer):TBigInteger;
      function getOutputBlockSize():integer;
      function  getInputBlockSize():integer;
      procedure init(lforEncryption:boolean;param:TRSAKeyParameters );
  end;
implementation
    {*
     * initialise the RSA engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param the necessary RSA key parameters.
     }
    procedure TRSACoreEngine.init(lforEncryption:boolean;param:TRSAKeyParameters );
    begin
      key := param;
      forEncryption := lforEncryption;
    end;

    {*
     * Return the maximum size for an input block to this engine.
     * For RSA this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     }
    function  TRSACoreEngine.getInputBlockSize():integer;
    var
      bitSize:integer;
    begin
        bitSize := key.getModulus().bitLength;

        if (forEncryption) then
        begin
            result := (bitSize + 7) div 8 - 1;
        end
        else
        begin
            result := (bitSize + 7) div 8;
        end;
    end;

    {*
     * Return the maximum size for an output block to this engine.
     * For RSA this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     }
    function TRSACoreEngine.getOutputBlockSize():integer;
    var
      bitSize:integer;
    begin
        bitSize := key.getModulus().bitLength;

        if (forEncryption) then
        begin
            result :=  (bitSize + 7) div 8;
        end
        else
        begin
            result :=  (bitSize + 7) div 8 - 1;
        end;
    end;

    function TRSACoreEngine.convertInput(inbuf:TBytes;inOff,inLen:integer):TBigInteger;
    var
      block:TBytes;
    begin
        if (inLen > (getInputBlockSize() + 1)) then
        begin
            Raise exception.create('input too large for RSA cipher.');
        end
        else if (inLen = (getInputBlockSize() + 1)) and (not forEncryption) then
        begin
            Raise exception.create('input too large for RSA cipher.');
        end;

        if (inOff <> 0) or (inLen <> length(inbuf)) then
        begin
            setlength(block,inLen);
            move(inbuf[inOff], block[0], inLen);
        end
        else
        begin
            block := inbuf;
        end;

        result := TBigInteger.create(1, block);
        if (result.compareTo(key.getModulus()) >= 0) then
        begin
            Raise exception.create('input too large for RSA cipher.');
        end;
    end;

    function TRSACoreEngine.convertOutput(r:TBigInteger):TBytes;
    var
      output,tmp:TBytes;
    begin
        output := r.toByteArray();
        if (forEncryption) then
        begin
            if (output[0] = 0) and (length(output) > getOutputBlockSize()) then       // have ended up with an extra zero byte, copy down.
            begin
                setlength(tmp,length(output) - 1);

                move(output[1], tmp[0], length(tmp));

                exit(tmp);
            end;

            if (length(output) < getOutputBlockSize()) then    // have ended up with less bytes than normal, lengthen
            begin
                setlength(tmp,getOutputBlockSize());

                move(output[0], tmp[length(tmp) - length(output)], length(output));

                exit(tmp);
            end;

            result := output;
        end
        else
        begin
            if (output[0] = 0) then        // have ended up with an extra zero byte, copy down.
            begin
                setlength(result,length(output) - 1);

                move(output[1], result[0], length(result));
            end
            else        // maintain decryption time
            begin
                setlength(result,length(output));

                move(output[0], result[0], length(result));
            end;

            fillbyte(output[0], length(output),0);
        end;
    end;
    function TRSACoreEngine.processBlock(inbuf:Tbytes;inOff,inLen:integer):Tbytes;
    var
      input,rr,e,m,r,blindedInput,blindedResult,rInv:TBigInteger;
      k:TRSAPrivateCrtKeyParameters;
    begin
      if (key = nil) then
      begin
          Raise exception.create('RSA engine not initialised');
      end;

      input := convertInput(inbuf, inOff, inLen);
      if (key is TRSAPrivateCrtKeyParameters) then
      begin
           k := TRSAPrivateCrtKeyParameters(key);

          e := k.getPublicExponent();
          //if (e <> nil) then   // can't do blinding without a public exponent
          //begin
          //    m := k.getModulus();
          //    r := TBigInteger.createRandomInRange(ONE, m.subtract(ONE), random);
          //
          //    blindedInput  := r.modPow(e, m).multiply(input).&mod(m);
          //    blindedResult := processBlock(blindedInput);
          //
          //    rInv := TBigInteger.modOddInverse(m, r);
          //    r := blindedResult.multiply(rInv).&mod(m);
          //    // defence against Arjen Lenstra’s CRT attack
          //    if (not input.equals(rr.modPow(e, m))) then
          //    begin
          //        Raise Exception.create('RSA engine faulty decryption/signing detected');
          //    end;
          //end
          //else
          //begin
              rr := processBlock(input);
          //end;
      end
      else
      begin
          rr := processBlock(input);
      end;

      result :=convertOutput(rr);
    end;
    function TRSACoreEngine.processBlock(input:TBigInteger):TBigInteger;
    var
      crtKey:TRSAPrivateCrtKeyParameters;
      p,q,dP,dQ,qInv,mP, mQ, h, m:TBigInteger;
    begin
        if (key is TRSAPrivateCrtKeyParameters) then
        begin
            //
            // we have the extra factors, use the Chinese Remainder Theorem - the author
            // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
            // advice regarding the expression of self.
            //
            crtKey := TRSAPrivateCrtKeyParameters(key);

            p    := crtKey.getP();
            q    := crtKey.getQ();
            dP   := crtKey.getDP();
            dQ   := crtKey.getDQ();
            qInv := crtKey.getQInv();

            // mP = ((input mod p) ^ dP)) mod p
            mP := (input.remainder(p)).modPow(dP, p);

            // mQ = ((input mod q) ^ dQ)) mod q
            mQ := (input.remainder(q)).modPow(dQ, q);

            // h = qInv * (mP - mQ) mod p
            h := mP.subtract(mQ);
            h := h.multiply(qInv);
            h := h.&Mod(p);               // mod (in Java) returns the positive residual

            // m = h * q + mQ
            m := h.multiply(q);
            m := m.add(mQ);

            result := m;
        end
        else
        begin
            result := input.modPow(key.getExponent(), key.getModulus());
        end;
    end;
    class procedure TRSACoreEngine.boot();
    begin
      ONE := TBigInteger.valueOf(1);
    end;
initialization
  TRSACoreEngine.boot();
end.
