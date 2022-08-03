unit ClpRSAPrivateCrtKeyParameters;
interface

uses clpBigInteger,ClpRSAKeyParameters;
type
    TRSAPrivateCrtKeyParameters = class(TRSAKeyParameters)
    private 
      e,p,q,dP,dQ,qInv:TBigInteger;
    public
      constructor create(modulus,publicExponent,privateExponent,lp,lq,ldP,ldQ,lqInv:TBigInteger);
      function getPublicExponent():TBigInteger;
      function getP():TBigInteger;
      function getQ():TBigInteger;
      function getDP():TBigInteger;
      function getDQ():TBigInteger;
      function getQInv():TBigInteger;
  end;
implementation
    {**
     * 
     *}
    constructor TRSAPrivateCrtKeyParameters.create(
        modulus,
        publicExponent,
        privateExponent,
        lp,
        lq,
        ldP,
        ldQ,
        lqInv:TBigInteger);
    begin
        inherited create(true, modulus, privateExponent);
        self.e    := publicExponent;
        self.p    := lp;
        self.q    := lq;
        self.dP   := ldP;
        self.dQ   := ldQ;
        self.qInv := lqInv;
    end;

    function TRSAPrivateCrtKeyParameters.getPublicExponent():TBigInteger;
    begin
        result := e;
    end;

    function TRSAPrivateCrtKeyParameters.getP():TBigInteger;
    begin
        result := p;
    end;

    function TRSAPrivateCrtKeyParameters.getQ():TBigInteger;
    begin
        result := q;
    end;

    function TRSAPrivateCrtKeyParameters.getDP():TBigInteger;
    begin
        result := dP;
    end;

    function TRSAPrivateCrtKeyParameters.getDQ():TBigInteger;
    begin
        result := dQ;
    end;

    function TRSAPrivateCrtKeyParameters.getQInv():TBigInteger;
    begin
        result := qInv;
    end;
end.
