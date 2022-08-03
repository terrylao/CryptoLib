Unit Clp3DESEngine;
interface

uses Sysutils,clpIBlockCipher,Clppack,ClpCryptoLibTypes,ClpICipherParameters,ClpIKeyParameter,ClpDESEngine,ClpI3DesEngine;
const
  BLOCK_SIZE = 8;
{*
 * a class that provides a basic DESede (or Triple DES) engine.
 }
 type
  T3DESEngine=class sealed(TDESEngine, I3DesEngine)
  private
    workingKey1,workingKey2,workingKey3:TCryptoLibUInt32Array;
    forEncryption:boolean;
  public
    constructor create();
    function GetIsPartialBlockOkay: Boolean;
    procedure init(encrypting:boolean;const params:ICipherParameters);
    function getAlgorithmName():string;
    function getBlockSize():integer;
    function processBlock(const inbuf:TBytes;inOff:integer;const outbuf:TBytes;outOff:integer):integer;
    procedure reset();
    function getCurrentKey():TCryptoLibByteArray;
    function getCurrentIV():TCryptoLibByteArray;override;
    procedure changeIV(modifier:TCryptoLibByteArray);
  end;
implementation
    {*
     * standard constructor.
     }
    constructor T3DESEngine.create();
    begin
    end;

    {*
     * initialise a DESede cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     }
    procedure T3DESEngine.init(encrypting:boolean;const params:ICipherParameters);
    var
      keyParameter: IKeyParameter;
      keyMaster,key1,key2,key3:TBytes;
    begin
        if not Supports(params, IKeyParameter, keyParameter) then
        begin
            Raise Exception.create('invalid parameter passed to DESede init - ');
        end;

        keyMaster := KeyParameter.getKey();

        if (length(keyMaster) <> 24) and (length(keyMaster) <> 16) then
        begin
            Raise Exception.create('key size must be 16 or 24 bytes.');
        end;

        forEncryption := encrypting;

        setlength(key1,8);
        move(keyMaster[0], key1[0], length(key1));
        workingKey1 := generateWorkingKey(encrypting, key1);

        setlength(key2,8);
        move(keyMaster[8], key2[0], length(key2));
        workingKey2 := generateWorkingKey(not encrypting, key2);

        if (length(keyMaster) = 24) then
        begin
            setlength(key3,8);
            move(keyMaster[16], key3[0], length(key3));
            workingKey3 := generateWorkingKey(encrypting, key3);
        end
        else    // 16 byte key
        begin
            workingKey3 := workingKey1;
        end;
    end;

    function T3DESEngine.getAlgorithmName():string;
    begin
        result := '3DES';
    end;

    function T3DESEngine.getBlockSize():integer;
    begin
        result := BLOCK_SIZE;
    end;

    function T3DESEngine.processBlock(const inbuf:TBytes;inOff:integer;const outbuf:TBytes;outOff:integer):integer;
    var
      temp:TBytes;
    begin
        if (workingKey1 = nil) then
        begin
            Raise Exception.create('DESede engine not initialised');
        end;

        if ((inOff + BLOCK_SIZE) > length(inbuf)) then
        begin
            Raise Exception.create('input buffer too short');
        end;

        if ((outOff + BLOCK_SIZE) > length(outbuf)) then
        begin
            Raise Exception.create('output buffer too short');
        end;

        setlength(temp,BLOCK_SIZE);

        if (forEncryption) then
        begin
            desFunc(workingKey1, inbuf, inOff, temp, 0);
            desFunc(workingKey2, temp, 0, temp, 0);
            desFunc(workingKey3, temp, 0, outbuf, outOff);
        end
        else
        begin
            desFunc(workingKey3, inbuf, inOff, temp, 0);
            desFunc(workingKey2, temp, 0, temp, 0);
            desFunc(workingKey1, temp, 0, outbuf, outOff);
        end;

        result := BLOCK_SIZE;
    end;
    function T3DESEngine.GetIsPartialBlockOkay: Boolean;
    begin
        result:=false;
    end;

    procedure T3DESEngine.reset();
    begin
    end;
    function T3DESEngine.getCurrentIV():TCryptoLibByteArray;
    begin
      // nothing to do.
    end;
    function T3DESEngine.getCurrentKey():TCryptoLibByteArray;
    begin
      //result:=workingKey;
    end;
    procedure T3DESEngine.changeIV(modifier:TCryptoLibByteArray);
    begin
      // nothing to do.
    end;
end.
