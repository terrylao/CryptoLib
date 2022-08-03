unit ClpRSAKeyParameters;
interface

uses clpBigInteger,sysutils,ClpICipherParameters,ClpAsymmetricKeyParameter;

type
  TRSAKeyParameters = class(TAsymmetricKeyParameter)
  private
    modulus,exponent:TBigInteger;
    // Hexadecimal value of the product of the 131 smallest odd primes from 3 to 743
    class var SMALL_PRIMES_PRODUCT:TBigInteger;
    class var ONE:TBigInteger;
    class procedure boot();
  protected
    function validate(lmodulus:TBigInteger):TBigInteger;
  public
    constructor create(lisPrivate:boolean;lmodulus,lexponent:TBigInteger);
    function getExponent():TBigInteger;
    function getModulus():TBigInteger;
  end;
implementation
    constructor TRSAKeyParameters.create(lisPrivate:boolean;lmodulus,lexponent:TBigInteger);
    begin
    inherited create(lisPrivate);

        if (not lisPrivate) then
        begin
            if ((lexponent.Int32Value and 1) = 0) then
            begin
                Raise exception.create('RSA publicExponent is even');
            end;
        end;

        self.modulus  := validate(lmodulus);
        self.exponent := lexponent;
    end;   

    function TRSAKeyParameters.validate(lmodulus:TBigInteger):TBigInteger;
    begin
        if ((lmodulus.int32Value and 1) = 0) then
        begin
            Raise exception.create('RSA modulus is even');
        end;

        if (not lmodulus.gcd(SMALL_PRIMES_PRODUCT).equals(ONE)) then
        begin
            Raise exception.create('RSA modulus has a small prime factor');
        end;

        // TODO: add additional primePower/Composite test - expensive!!

        result := lmodulus;
    end;

    function TRSAKeyParameters.getModulus():TBigInteger;
    begin
        result :=  modulus;
    end;

    function TRSAKeyParameters.getExponent():TBigInteger;
    begin
        result :=  exponent;
    end;
    class procedure TRSAKeyParameters.boot();
    begin
      SMALL_PRIMES_PRODUCT := TBigInteger.create(
              '8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f'
            + '73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2'
            + 'ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8'
            + 'f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f',
        16);
      ONE := TBigInteger.valueOf(1);
    end;
initialization
  TRSAKeyParameters.boot();
end.
