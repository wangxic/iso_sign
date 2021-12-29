# iso_sign
ios 超级签名


# ios 超级签名（开发团队签名）

## 1.生成描述文件.mobileconfig

（1）使用ssl 签名

mobileconfig 文件格式

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadContent</key>
        <dict>
            <key>URL</key>
            <string>https://dev.skyfox.org/udid/receive.php</string>  // 回调地址 必须使用https 返回uuid
            <key>DeviceAttributes</key>
            <array>
                <string>UDID</string>
                <string>IMEI</string>
                <string>ICCID</string>
                <string>VERSION</string>
                <string>PRODUCT</string>
            </array>
        </dict>
        <key>PayloadOrganization</key>
        <string>dev.skyfox.org</string>
        <key>PayloadDisplayName</key>
        <string>查询设备UDID</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadUUID</key>
        <string>3C4DC7D2-E475-3375-489C-0BB8D</string>
        <key>PayloadIdentifier</key>
        <string>dev.skyfox.profile-service</string>
        <key>PayloadDescription</key>
        <string>本文件仅用来获取设备ID</string> 
        <key>PayloadType</key>
        <string>Profile Service</string>
    </dict>
</plist>
```

```
mobileconfig文件的签名和认证（signed、verified
基于IOS上MDM技术相关ziliao整理及汇总 mobileconfig文件的签名和认证（signed、verified）
一、功能描述：
鉴于我们的设备和MDM server之间已经可以通信，并能完成相应的锁屏、擦除数据、查询设备信息等功能，但是，我们在安装了mobileconfig后，返现配置描述文件打开显示“unsigned” 或者“尚未签名”这样的情况，所以接下来的工作就是让我们的mobileconfig文件看起来更加安全一些。
二、操作步骤：
1、确保我们有如下文件：
  （1）、mbaike.crt（https服务器端使用证书文件）
  （2）、mbaike.key（https服务器端使用证书对应的密钥）
  （3）、ca-bundle.pem（startssl官网下载的跟证书文件，具体的在哪里下载，请在startssl控制面板中查找）
  （4）、unsigned.mobilecofig文件（IOS端生成的未签名的配置描述文件）
2、在linux上通过openssl命令生成签名后的signed.mobileconfig文件：
openssl smime -sign -in unsigned.mobileconfig -out signed.mobileconfig -signer mbaike.crt -inkey mbaike.key -certfile ca-bundle.pem -outform der -nodetach
注意：在使用上面的openssl命令的时候会要求输入key文件的密码，我们这里不建议使用这种方式，我们把key文件的密码写入到key文件中，这样就不需要输入密码了，详见第三步；
3、将key的密码写入key文件：
openssl rsa -in mbaike.key -out mbaikenopass.key
故，第二步中的命令变成了：
openssl smime -sign -in unsigned.mobileconfig -out signed.mobileconfig -signer mbaike.crt -inkey mbaikenopass.key -certfile ca-bundle.pem -outform der -nodetach
这样就不需要输入密码了，这一步，我们得到了signed.mobileconfig这个文件，这个文件就是我们得到的签名和认证后的文件，我们安装到移动设备中，mobileconfig配置描述文件变成了绿色的“Verified”了。
备注：因为我们的mobileconfig配置描述文件一般都是动态生成的，因为文件中含有“Check In URL” 和“Server URL ”两个动态的地址，所以需要通过java程序动态调用openssl命令来生成签名后的文件，这里我们后面介绍。

```

## 2.获取uuid

通过 mobileconfig  回调地址获取uuid

```php
$data = file_get_contents('php://input');
$plistBegin   = '<?xml version="1.0"';
$plistEnd   = '</plist>';
$pos1 = strpos($data, $plistBegin);
$pos2 = strpos($data, $plistEnd);
$data2 = substr ($data,$pos1,$pos2-$pos1);
$xml = xml_parser_create();
xml_parse_into_struct($xml, $data2, $vs);
xml_parser_free($xml);
$UDID = "";
$CHALLENGE = "";
$DEVICE_NAME = "";
$DEVICE_PRODUCT = "";
$DEVICE_VERSION = "";
$iterator = 0;
$arrayCleaned = array();
foreach($vs as $v){
    if($v['level'] == 3 && $v['type'] == 'complete'){
        $arrayCleaned[]= $v;
    }
    $iterator++;
}

$data = "";
$iterator = 0;
foreach($arrayCleaned as $elem){
    $data .= "\n==".$elem['tag']." -> ".$elem['value']."<br/>";
    switch ($elem['value']) {
        case "CHALLENGE":
            $CHALLENGE = $arrayCleaned[$iterator+1]['value'];
            break;
        case "DEVICE_NAME":
            $DEVICE_NAME = $arrayCleaned[$iterator+1]['value'];
            break;
        case "PRODUCT":
            $DEVICE_PRODUCT = $arrayCleaned[$iterator+1]['value'];
            break;
        case "UDID":
            $UDID = $arrayCleaned[$iterator+1]['value'];
            break;
        case "VERSION":
            $DEVICE_VERSION = $arrayCleaned[$iterator+1]['value'];
            break;                       
    }
    $iterator++;
}
$params = "UDID=".$UDID."&CHALLENGE=".$CHALLENGE."&DEVICE_NAME=".$DEVICE_NAME."&DEVICE_PR ODUCT=".$DEVICE_PRODUCT."&DEVICE_VERSION=".$DEVICE_VERSION;
```

## 3.生成证书文件

#### 1.准备 配置文件

```.php
$acc_id = 1001; //
$key_id = 'Z73F82D8'; //key
$issuser = "aabd8d-2d5a-4d20-ace0-27f44b59ff1a"; // issuser
//p8 证书文件
$authKey = '-----BEGIN PRIVATE KEY-----   
6v3+lCJy
-----END PRIVATE KEY-----';
//团队id
$team_id = "43LANAT4X8";
// 包名
$identifier = "com.game733.fish2.com";
```

#### 2.获取token

##### 2.1签名文件

```php
class JWT{
    /**
     * sign
     * @param $payload
     * @param $header
     * @param $key
     * @return string
     * @throws Exception
     */
    public static function sign($payload, $header, $key)
    {
        $segments = [];
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::_sign($signing_input, $key);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * openssl_sign
     * @param $msg
     * @param $key
     * @return string
     * @throws Exception
     */
    private static function _sign($msg, $key)
    {
        $key = openssl_pkey_get_private($key);
        if (!$key) {
            throw new \Exception(openssl_error_string());
        }

        $signature = '';
        $success = openssl_sign($msg, $signature, $key, OPENSSL_ALGO_SHA256);
        if (!$success) {
            throw new \Exception("OpenSSL unable to sign data");
        } else {
            $signature = self::fromDER($signature, 64);
            return $signature;
        }
    }

    /**
     * jsonDecode
     * @param $input
     * @return mixed
     * @throws Exception
     */
    private static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            $max_int_length = strlen((string)PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{' . $max_int_length . ',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            throw new \Exception(json_last_error_msg());
        } elseif ($obj === null && $input !== 'null') {
            throw new \Exception('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * jsonEncode
     * @param $input
     * @return false|string
     * @throws Exception
     */
    private static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            throw new \Exception(json_last_error_msg());
        } elseif ($json === 'null' && $input !== null) {
            throw new \Exception('Null result with non-null input');
        }
        return $json;
    }

    /**
     * urlsafeB64Decode
     * @param $input
     * @return false|string
     */
    private static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * urlsafeB64Encode
     * @param $input
     * @return mixed
     */
    private static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * toDER
     * @param string $signature
     * @param int $partLength
     * @return string
     * @throws Exception
     */
    private static function toDER(string $signature, int $partLength): string
    {
        $signature = \unpack('H*', $signature)[1];
        if (\mb_strlen($signature, '8bit') !== 2 * $partLength) {
            throw new \Exception('Invalid length.');
        }
        $R = \mb_substr($signature, 0, $partLength, '8bit');
        $S = \mb_substr($signature, $partLength, null, '8bit');
        $R = self::preparePositiveInteger($R);
        $Rl = \mb_strlen($R, '8bit') / 2;
        $S = self::preparePositiveInteger($S);
        $Sl = \mb_strlen($S, '8bit') / 2;
        $der = \pack('H*',
            '30' . ($Rl + $Sl + 4 > 128 ? '81' : '') . \dechex($Rl + $Sl + 4)
            . '02' . \dechex($Rl) . $R
            . '02' . \dechex($Sl) . $S
        );
        return $der;
    }

    /**
     * toDER
     * @param string $der
     * @param int $partLength
     * @return string
     */
    private static function fromDER(string $der, int $partLength): string
    {
        $hex = \unpack('H*', $der)[1];
        if ('30' !== \mb_substr($hex, 0, 2, '8bit')) { // SEQUENCE
            throw new \RuntimeException();
        }
        if ('81' === \mb_substr($hex, 2, 2, '8bit')) { // LENGTH > 128
            $hex = \mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = \mb_substr($hex, 4, null, '8bit');
        }
        if ('02' !== \mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Rl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $R = self::retrievePositiveInteger(\mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R = \str_pad($R, $partLength, '0', STR_PAD_LEFT);
        $hex = \mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if ('02' !== \mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Sl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $S = self::retrievePositiveInteger(\mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S = \str_pad($S, $partLength, '0', STR_PAD_LEFT);
        return \pack('H*', $R . $S);
    }

    /**
     * preparePositiveInteger
     * @param string $data
     * @return string
     */
    private static function preparePositiveInteger(string $data): string
    {
        if (\mb_substr($data, 0, 2, '8bit') > '7f') {
            return '00' . $data;
        }
        while ('00' === \mb_substr($data, 0, 2, '8bit') && \mb_substr($data, 2, 2, '8bit') <= '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }
        return $data;
    }

    /**
     * retrievePositiveInteger
     * @param string $data
     * @return string
     */
    private static function retrievePositiveInteger(string $data): string
    {
        while ('00' === \mb_substr($data, 0, 2, '8bit') && \mb_substr($data, 2, 2, '8bit') > '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }
        return $data;
    }
}
```

##### 2.2签名

```php
$header = ["alg"=>"ES256","kid"=>$key_id,"typ"=>"JWT"];
$payload = ['iss'=>$issuser,'exp'=>15*60,"aud"=>"appstoreconnect-v1"];  //exp = 15分钟*60秒
$token =  JWT::sign($payload, $header, $this->authKey);
return $token;
```

### 3.通过api接口获取p12文件、和p12key

#### 1.获取 私人密钥 

```.php
substr($email,0,stripos($email,'@'));
getCertificateSigningRequest($name,$email);

public function getCertificateSigningRequest($commonName, $emailAddress) {
        $privateKeyParam = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];
        $privateKey = openssl_pkey_new($privateKeyParam);
        $subject = [
            'commonName' => $commonName,
            'emailAddress' => $emailAddress
        ];
        $certificateSigningRequest = openssl_csr_new($subject, $privateKey);
        openssl_pkey_export($privateKey, $pkey);
        openssl_csr_export($certificateSigningRequest, $csr);
        return [
            'private_key' => $pkey,
            'csr' => $csr
        ];
}
```

#### 2.获取 cert_id证书ID

```php
public function get_distribution_pem($acc,$csr){
	$data = $this->createCertificate($csr);
	if(isset($data['errors'])) {    
	//记录错误日志。
	} else if(isset($data['data']['attributes']['certificateContent'])) {
	    return ['cert_id'=> $data['data']['id'], 'file'=>$this->explainCert($data['data']['attributes']['certificateContent'],$acc_id)];
	}
}

public function createCertificate($csrContent,$certificateType = 'IOS_DISTRIBUTION')
    {
        $params = [
            'data' => [
                'type' => 'certificates',
                'attributes' => [
                    'csrContent' => $csrContent,
                    'certificateType' => $certificateType
                ]
            ]
        ];
        return $this->curlPost('https://api.appstoreconnect.apple.com/v1/certificates',$params);
}
    
    
protected function curlPost($uri , $data=array()){
        if(substr($uri,0,1)!='/') {
            $uri = '/'.$uri;
        }
        $ch = curl_init();

        $header =   ['Authorization: Bearer '.$this->getAuthToken(),'Content-Type: application/json'];
        if(!empty($header)){
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
            curl_setopt($ch, CURLOPT_HEADER, 0);//返回response头部信息
        }
        curl_setopt($ch, CURLOPT_URL, $this->apiURL.$uri);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        // POST数据
        curl_setopt($ch, CURLOPT_POST, 1);
        // 把post的变量加上
        curl_setopt($ch, CURLOPT_POSTFIELDS,json_encode($data));
        $output = curl_exec($ch);
        $tmp = [];
        curl_close($ch);
        $output && $tmp = json_decode($output,true);
        return $tmp;
    }
```

