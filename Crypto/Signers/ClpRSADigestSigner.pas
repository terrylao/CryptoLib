unit ClpRSADigestSigner;
interface

uses clpBigInteger,ClpRSAKeyParameters,sysutils,ClpArrayUtils,ClpAsn1Objects,ClpIAsymmetricKeyParameter,
  ClpRSACoreEngine,ClpISigner,ClpICipherParameters,ClpIDigest,ClpAsymmetricKeyParameter;

Type
  TRSADigestSigner = class//(TInterfacedObject, ISigner)
    private 
      rsaEngine:TRSACoreEngine;
      digest:IDigest;
      forSigning:boolean;
      function derEncode(hash:TBytes):TBytes;
      function GetAlgorithmName: String;
    public
      procedure reset();
      function verifySignature(const signature:Tbytes):boolean;
      procedure init(lforSigning:boolean;const parameters:TRSAKeyParameters);
      procedure BlockUpdate(const input:TBytes;inOff,length:integer);
      procedure Update(input: Byte);
      function generateSignature():TBytes;
      constructor create(ldigest:IDigest);
      property AlgorithmName: String read GetAlgorithmName;
  end;
implementation
    function TRSADigestSigner.GetAlgorithmName: String;
    begin
      result := 'RSA';
    end;
    procedure TRSADigestSigner.Update(input: Byte);
    begin

    end;

    constructor TRSADigestSigner.create(ldigest:IDigest);
    begin
        digest:=ldigest;
        rsaEngine:=TRSACoreEngine.create;
    end;

    {*
     * Initialize the signer for signing or verification.
     *
     * @param forSigning
     *            true if for signing, false otherwise
     * @param parameters
     *            necessary parameters.
     }
    procedure TRSADigestSigner.init(lforSigning:boolean;const parameters:TRSAKeyParameters);
    begin
        forSigning := lforSigning;
        if (forSigning) and (not parameters.isPrivate) then
        begin
            Raise exception.create('signing requires private key');
        end;

        if (not forSigning) and (parameters.isPrivate) then
        begin
            Raise exception.create('verification requires public key');
        end;

        reset();

        rsaEngine.init(forSigning, parameters);
    end;

    {*
     * update the internal digest with the byte array in
     }
    procedure TRSADigestSigner.BlockUpdate(const input:TBytes;inOff,length:integer);
    begin
        digest.BlockUpdate(input, inOff, length);
    end;

    {*
     * Generate a signature for the message we've been loaded with using the key
     * we were initialised with.
     }
    function TRSADigestSigner.generateSignature():TBytes;
    var
      hash,data:TBytes;
    begin
        if (not forSigning) then
        begin
            Raise exception.create('RSADigestSigner not initialised for signature generation.');
        end;

        setlength(hash,digest.getDigestSize());
        digest.doFinal(hash, 0);

        try
            data := derEncode(hash);
            result := rsaEngine.processBlock(data, 0, length(data));
        except
            Raise exception.create('unable to encode signature: ');
        end;
    end;

    {*
     * return true if the internal state represents the signature described in
     * the passed in array.
     }
    function TRSADigestSigner.verifySignature(const signature:Tbytes):boolean;
    var
      hash,sig,expected:TBytes;
      sigOffset,expectedOffset,nonEqual,i:integer;
    begin
        if (forSigning) then
        begin
            Raise exception.create('RSADigestSigner not initialised for verification');
        end;

        setlength(hash,digest.getDigestSize());
        digest.doFinal(hash, 0);

        try
            sig := rsaEngine.processBlock(signature, 0, length(signature));
            expected := derEncode(hash);
        except
            exit(false);
        end;

        if (length(sig) = length(expected)) then
        begin
            exit(TArrayUtils.ConstantTimeAreEqual(sig, expected));
        end
        else if (length(sig) = length(expected) - 2) then  // NULL left out
        begin
            sigOffset      := length(sig) - length(hash) - 2;
            expectedOffset := length(expected) - length(hash) - 2;

            expected[1] :=expected[1] - 2;      // adjust lengths
            expected[3] :=expected[3] - 2;

            nonEqual := 0;

            for i := 0 to length(hash) -1 do
            begin
                nonEqual :=nonEqual or (sig[sigOffset + i] xor expected[expectedOffset + i]);
            end;

            for i := 0 to sigOffset -1 do
            begin
                nonEqual :=nonEqual or (sig[i] xor expected[i]);  // check header less NULL
            end;

            result := nonEqual = 0;
        end
        else
        begin
          TArrayUtils.ConstantTimeAreEqual(expected, expected);// keep time 'steady'.

          result := false;
        end;
    end;

    procedure TRSADigestSigner.reset();
    begin
        digest.reset();
    end;

    function TRSADigestSigner.derEncode(hash:TBytes):TBytes;
    var
      asn1:TDerOctetString;
    begin
        asn1:=TDerOctetString.Create(hash);
        result := asn1.getEncoded('DER');
    end;
end.
