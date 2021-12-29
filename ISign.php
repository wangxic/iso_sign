<?php 

include_once "./JWT.php";
include_once "./Redisv.php";
class ISign{
	// 接口地址
	var $apiURL = 'https://api.appstoreconnect.apple.com/v1';
	// 数据库 纪录的配置id
    var $acc;
    // token 有效时间
    var $timeout = 15;//token有效时间，15分钟
    var $filePath = BASEPATH."../application/libraries/iso_sign";
    /**
    * - 1.一个可用的苹果开发者账号
		- 2.请求App Store Connect API访问权限。登录：App Store Connect后台，“用户和访问” - “密钥”，点击“请求访问权限”。只有agent才有权限。
		- 3.生成密钥。
		- 进入appstore中->用户管理->秘钥->创建（管理）,然后获取到：issuer id,key id,下载秘钥(*.p8) 申请访问权限后，才会看到“生成密钥”的按钮，点击“生成密钥”，根据提示起个名字，完成后会产生一个“Issuer ID”和“密钥ID”，这两个参数后面生成token需要用到。下载密钥，密钥是一个.p8的文件，注意：私钥只能下载一次，永远不会过期，保管好，如果丢失了，去App Store Connect后台撤销密钥，否则别人拿到也可以用。
     */
    var $key_id,$issuser,$authKey;
  	public function __construct(){
      $this->_ci = get_instance();

    }

  	/**
  	 * 设置参数
  	 */
    public function setCfg($acc_id,$key_id,$issuser,$authKey,$filePath="./temp"){
        $this->acc = $acc_id;
        $this->key_id = $key_id;
        $this->issuser = $issuser;
        $this->authKey = $authKey;
        $this->filePath = $filePath;
        $this->getAuthToken();
    }
  	/**
     * 获取token
     * @throws Exception
     */
    public function getAuthToken() {
        $key = "api_token_".$this->acc;
        $this->Redisv = new Redisv();
        $config = $this->_ci->config->item('redis');
        $this->Redisv->set_param('config',$config);
        $token =$this->Redisv->get($key);

        if($token =$this->Redisv->get($key)) {
          return $token[0];
        }

        $header = ["alg"=>"ES256","kid"=>$this->key_id,"typ"=>"JWT"];
        $payload = ['iss'=>$this->issuser,'exp'=>time()+($this->timeout+2)*60,"aud"=>"appstoreconnect-v1"];
      
        $this->JWT = new JWT();

        $token =  $this->JWT->sign($payload, $header, $this->authKey);

        $res = $this->Redisv->set($key,json_encode([$token]), $this->timeout*60);

        return $token;
    }


    protected function curlGet($uri,$params = []){
        if(substr($uri,0,1)!='/') {
            $uri = '/'.$uri;
        }
        $curl = curl_init();
        $token = $this->getAuthToken();
        $header =   ['Authorization: Bearer '.$token,'Content-Type:application/json'];
        if(!empty($header)){
            curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
            curl_setopt($curl, CURLOPT_HEADER, 0);//返回response头部信息
        }
        $str = '';
        if($params){
            $str = '?'.http_build_query($params);
        }
        curl_setopt($curl, CURLOPT_URL, $this->apiURL.$uri.$str);
        curl_setopt($curl, CURLOPT_HTTPGET, 1);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);//绕过ssl验证
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        $output = curl_exec($curl);
        $tmp = [];
        $output && $tmp = json_decode($output,true);
        curl_close($curl);
        return $tmp;
    }

    function curlDel($uri,$params=[]) {
        if(substr($uri,0,1)!='/') {
            $uri = '/'.$uri;
        }
        $token = $this->getAuthToken();
        $ch = curl_init();
        $header =   ['Authorization: Bearer '.$token,'Content-Type:application/json'];
        if(!empty($header)){
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
            curl_setopt($ch, CURLOPT_HEADER, 0);//返回response头部信息
        }
        if($params){
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($params));
        }
        curl_setopt($ch, CURLOPT_URL, $this->apiURL.$uri);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);//绕过ssl验证
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $output = curl_exec($ch);
        $tmp = [];
        $output && $tmp = json_decode($output,true);
        curl_close($ch);
        return $tmp;
    }

    function curlPatch($uri,$params=[]) {
        if(substr($uri,0,1)!='/') {
            $uri = '/'.$uri;
        }
        $ch = curl_init();
        $token = $this->getAuthToken();
        $header =   ['Authorization: Bearer '.$token,'Content-Type:application/json'];
        if(!empty($header)){
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
            curl_setopt($ch, CURLOPT_HEADER, 0);//返回response头部信息
        }
        curl_setopt ($ch,CURLOPT_URL,$this->apiURL.$uri);
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_setopt($ch, CURLOPT_POSTFIELDS,json_encode($params));     //20170611修改接口，用/id的方式传递，直接写在url中了
        $output = curl_exec($ch);
        $tmp = [];
        $output && $tmp = json_decode($output,true);
        curl_close($ch);
        return $tmp;
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

    /**
     * 列出所有app
     */
    public function listAllApps(){
        return $this->curlGet('/apps');
    }

    /**
     * 验证token
     */
    private function TestToken(){
        $ret = $this->curlGet('/apps');
        var_dump($ret);
        //$cmd = "curl -v -H 'Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Ijk2RENaR0JSOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJjZTY0M2UzMS0xOWI0LTQxNjMtYjlmMC1jOTJmYmFiZWFjN2QiLCJleHAiOjE1OTIyMDc1NjQsImF1ZCI6ImFwcHN0b3JlY29ubmVjdC12MSJ9.Ounk5l3JC85rRkhJ5ApWh7ctkSkFPumbBRQgMTTx7AAXCdWaK1e41Q2lS-cumR6sK9XFE8B9CypZvZvhgA__HQ' \"https://api.appstoreconnect.apple.com/v1/apps\"";
    }

    /**
     * 获取开发团队的成员列表。
     */
    public function getDevUsers(){
        return $this->curlGet('/users');
    }

    //分析.
    private function explainCert($con,$acc){
        $str = base64_decode($con);
        $path = $this->filePath.'/p12/'.$acc;
        if(!is_dir($path)) {
            mkdir($path);
            chmod($path, 0777);
        }
        $tf = $path.'/'.'distribution'.'.cer';
        file_put_contents($tf,$str);
        return $tf;
    }

    private function getAppleWWDRCA(){
        $f = '/tmp/AppleWWDRCA.pem';
        if(!file_exists($f)) {  //不存在则下载，并导出.
            $con = file_get_contents('http://developer.apple.com/certificationauthority/AppleWWDRCA.cer');
            if($con) {
                $t = '/tmp/apple.cer';
                file_put_contents($t,$con);
                exec("openssl x509 -in {$t} -inform DER -out {$f} -outform PEM",$ar,$ret);
                if($ret == 0){
                    unlink($t);
                    return $f;
                }
                return false;
            }
        }
        return $f;
    }
    private function delFiles($files){
        foreach ($files as $f) {
            @unlink($f);
        }
    }

    //********************************* 具体的逻辑 ************************************

    /**
     * 1.获取CSR文件。
     */
    public function getCSR($email){
        $name = substr($email,0,stripos($email,'@'));
        return $this->getCertificateSigningRequest($name,$email);
    }

    /**
     * 2.获取distribution_key.pem文件。
     */
    public function get_distribution_pem($acc,$csr){
        //判断当前账户有多少个IOS_DISTRIBUTION,如果超过2个，则需要删除一个，不然无法创建新的。
        $all = $this->showTypeCertificates();
        $flag = true;
        if(count($all)>=2) {
            $tmp = [];
            //删除最新的一个.
            foreach ($all as $k=>$row){
                if($tmp) { //如果有数据，则比较时间
                    if(strtotime($tmp['attributes']['expirationDate'])<strtotime($row['attributes']['expirationDate'])) {
                        $tmp = $row;
                    }
                }else{
                    $tmp = $row;
                }
            }
            //得到最新的。请求删除。
            $flag = $this->revokeCertificate($tmp['id']);

        }
        if($flag) {
            //创建新的。
            $data = $this->createCertificate($csr);
            if(isset($data['errors'])) {    //记录错误日志。
            } else if(isset($data['data']['attributes']['certificateContent'])) {
                return ['cert_id'=> $data['data']['id'], 'file'=>$this->explainCert($data['data']['attributes']['certificateContent'],$acc)];
            }
        }
        return false;
    }


    /**
     *
     * https://www.jason-z.com/post/160
     * @param $cer  为下载生成后的证书cer
     * @param $pri_key 为生成CSR时的创建的私钥。
     */
    public function exportP12($cer,$pri_key,$acc_id,$path){
        //wget http://developer.apple.com/certificationauthority/AppleWWDRCA.cer
        //openssl x509 -in AppleWWDRCA.cer -inform DER -out AppleWWDRCA.pem -outform PEM
        $apple = $this->getAppleWWDRCA();

        if(is_bool($apple)) {
            exit('export AppleWWDRCA error');
        }
        //导出cer为pem格式.
        $pri_file = '/tmp/pri_file';

        file_put_contents($pri_file,$pri_key);

        $dis_pem = '/tmp/ios_distribution.pem';
        //openssl x509 -inform der -in ios_distribution.cer -outform PEM -out ios_distribution.pem
        exec("openssl x509 -inform der -in {$cer} -outform PEM -out {$dis_pem}",$ar,$ret);

        if($ret){ //失败.
            exit('export error -1 ');
        }

        $p12 = $path.'/'.$acc_id.'.p12';
         $pwd =(string)rand(1000000000,9999999999);
        exec("openssl pkcs12 -export -out {$p12} -inkey {$pri_file} -in {$dis_pem} -certfile {$apple} -passout pass:'{$pwd}' ",$ar,$ret);
     
   

        $files = [$pri_file,$dis_pem];
        if($ret == 0) {
            $this->delFiles($files);
            return ['pwd'=>$pwd,'p12'=>$p12];
        }
        $this->delFiles($files);
        exit('export error -2');
    }

    /**
     * 获取设备剩余可使用的数量.
     */
    public function getDeviceNums($acc_id){
        $info = $this->listDevices();
        $num = 100;
        if(isset($info['data'])) {
            $num -= count($info['data']);
        }else{
            $num = 0;
        }
        return $num;
    }



    public function listDevices(array $query = ['fields[devices]'=>'addedDate, deviceClass, model, name, platform, status, udid']){
        return $this->curlGet('/devices',$query);
    }

    /**
     * 获取对应的udid的注册id.
     */
    public function getOneDevID($udid){
        $query = ['fields[devices]'=>'addedDate, deviceClass, model, name, platform, status, udid','filter[udid]'=>$udid];
        return $this->curlGet('/devices',$query);
    }


    /**
     * 获取某一个设备的信息。
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function readDeviceInformation($id, array $query = []){
        return $this->curlGet('/devices/'.$id,$query);
    }

    /**
     * 注册某一个设备.
     * @param $name
     * @param $udid
     * @param $platform Possible values: IOS, MAC_OS
     * @return mixed|string
     */
    public function registerDevice($name, $udid, $platform='IOS'){
        $params = [
            'data' => [
                'type' => 'devices',
                'attributes' => [
                    'name' => $name,
                    'platform' => $platform,
                    'udid' => $udid
                ]
            ]
        ];
        return $this->curlPost("/devices",$params);
    }

    /**
     * 修改设备的状态。
     * @param $id
     * @param $name
     * @param $status Possible values: ENABLED, DISABLED
     * @return mixed|string
     */
    public function modifyDevice($id, $name, $status){
        $json = [
            'data' => [
                'id' => $id,
                'type' => 'devices',
                'attributes' => [
                    'name' => $name,
                    'status' => $status
                ]
            ]
        ];
        return $this->curlPatch('/devices/' . $id,$json);
    }


       public function listBundleID(array $query = ['fields[bundleIds]'=>'name,identifier,platform']){
        return $this->curlGet('/bundleIds',$query);
    }

    /**
     * 获取已经存在的包名信息。
     * @param $indent
     * @return array|mixed
     */
    public function listOneBundleID($indent){
        $query = ['fields[bundleIds]'=>'name,identifier,platform','filter[identifier]'=>$indent];
        return $this->curlGet('/bundleIds',$query);
    }

    /**
     * 获取某一个信息。
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function readBundleIdInformation($id, array $query = []){
        return $this->curlGet('/bundleIds/'.$id,$query);
    }

    /**
     * 创建一个BundleID
    必传参数：（其它没列出来的参数表示写法固定，参考请求示例）
    name：取个名字
    identifier：bundle identifier
    seedId：Team ID
    platform：IOS，MAC_OS
    Status Code: 201 Created，表示成功
     * @param $identifier
     * @param $name
     * @param $seedId
     * @param $platform Possible values: IOS, MAC_OS
     * @return mixed|string
     */
    public function registerBundleID($identifier, $name,  $seedId = null,$platform='IOS'){
        $params = [
            'data' => [
                'type' => 'bundleIds',
                'attributes' => [
                    'identifier' => $identifier,
                    'name' => $name,
                    'platform' => $platform,
                    'seedId' => $seedId ?: ''
                ]
            ]
        ];
        return $this->curlPost("/bundleIds", $params);
    }

    /**
     * 删除bundleID
     * @param $id
     * @return array|mixed
     */
    public function deleteBundleID($id){
        $ret = $this->curlDel('/bundleIds/' . $id);
        return $ret == [] ? true : false;
    }


    /**
     * 获取bundle设置的ProfileID
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function listAllProfilesForABundleID($id, array $query = []){
        return $this->curlGet('/bundleIds/' . $id . '/profiles');
    }

    /**
     * 获取bundle设置的关联ProfileID
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function getAllProfileIDsForABundleID($id, array $query = []){
        return $this->curlGet('/bundleIds/' . $id . '/relationships/profiles');
    }


    /**
     * 获取Bundle的所有启用了的特权。
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function listAllCapabilitiesForABundleID($id, array $query = []){
        return $this->curlGet('/bundleIds/' . $id . '/bundleIdCapabilities');
    }

    /**
     * 获取Bundle的所有启用了的特权。
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function getAllCapabililityIDsForABundleID($id, array $query = []){
        return $this->curlGet('/bundleIds/' . $id . '/relationships/bundleIdCapabilities');
    }


    //********************* Capabilitty *********************

    /**
     * 启用某一个功能。
     * @param $bundleID
     * @param $capabilityType  Possible values: ICLOUD, IN_APP_PURCHASE, GAME_CENTER, PUSH_NOTIFICATIONS, WALLET,
     * INTER_APP_AUDIO, MAPS, ASSOCIATED_DOMAINS, PERSONAL_VPN, APP_GROUPS, HEALTHKIT, HOMEKIT,
     * WIRELESS_ACCESSORY_CONFIGURATION, APPLE_PAY, DATA_PROTECTION, SIRIKIT, NETWORK_EXTENSIONS, MULTIPATH, HOT_SPOT,
     * NFC_TAG_READING, CLASSKIT, AUTOFILL_CREDENTIAL_PROVIDER, ACCESS_WIFI_INFORMATION
     * @param array $settings
     * @return array|mixed
     */
    public function enableCapability($bundleID, $capabilityType, array $settings = []){
        $params = [
            'data' => [
                'type' => 'bundleIdCapabilities',
                'attributes' => [
                    'capabilityType' => $capabilityType,
                    'settings' => $settings
                ],
                'relationships' => [
                    'bundleId' => [
                        'data' => [
                            'id' => $bundleID,
                            'type' => 'bundleIds'
                        ]
                    ]
                ]
            ]
        ];
        return $this->curlPost("/bundleIdCapabilities", $params);
    }

    /**
     * 删除某一个功能
     * @param $bundleID
     * @return mixed
     */
    public function disableCapability($bundleID){
        return $this->curlDel('/bundleIdCapabilities/'. $bundleID);
    }

    /**
     * 修改某一个功能
     * @param $id
     * @param $capabilityType
     * @param array $settings
     * @return mixed
     */
    public function modifyCapability($bundleID, $capabilityType, array $settings = []){
        $data = [
            'data' => [
                'id' => $bundleID,
                'type' => 'bundleIdCapabilities',
                'attributes' => [
                    'capabilityType' => $capabilityType,
                    'settings' => $settings
                ]
            ]
        ];
        return $this->curlPatch('/bundleIdCapabilities/'. $bundleID,$data);
    }


     public function createProfile($name, $profileType, $bundleID, $certificateID, $deviceID){
        $certificates [] = [
            'id' => $certificateID,
            'type' => 'certificates'
        ];
        $devices [] = [
            'id' => $deviceID,
            'type' => 'devices'
        ];
        $params = [
            'data' => [
                'attributes' => [
                    'name' => $name,
                    'profileType' => $profileType
                ],
                'relationships' =>[
                    'bundleId' => [
                        'data' => [
                            'id' => $bundleID,
                            'type' => 'bundleIds'
                        ]
                    ],
                    'certificates' => [
                        'data' => $certificates
                    ],
                    'devices' => [
                        'data' => $devices
                    ],
                ],
                'type' => 'profiles',
            ]
        ];
        return $this->curlPost('/profiles',$params);
    }

    /**
     * 列出所有的Profile
     * @param array $query
     * @return array|mixed
     */
    public function listProfile(array $query = ['filter[profileType]'=>'IOS_APP_ADHOC','filter[profileState]'=>'ACTIVE']){
        return $this->curlGet('/profiles',$query);
    }


    /**
     * 删除某一个Profile
     * @param $id
     * @return array|mixed
     */
    public function deleteProfile($id){
        return $this->curlDel('/profiles/' . $id);
    }

    /**
     * 读取某一个profile
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function readProfileInformation($id, array $query = []){
        return $this->curlGet('/profiles/' . $id);
    }


    /**
     * 获取某个Provisioning bundleId详情
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function readBundleIDInProfile($id, array $query = []){
        return $this->curlGet('/profiles/' . $id . '/bundleId');
    }

    /**
     * 获取某个Provisioning Resource详情
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function getBundleIDResourceInProfile($id, array $query = []){
        return $this->curlGet('/profiles/' . $id . '/relationships/bundleId');
    }

    /**
     * 获取某个Provisioning certificates详情
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function listAllCertificatesInProfile($id, array $query = []){
        return $this->curlGet('/profiles/' . $id . '/certificates');
    }

    /**
     * 获取某个Provisioning  相关 certificates详情
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function getAllCertificateIDsInProfile($id, array $query = []){
        return $this->curlGet('/profiles/' . $id . '/relationships/certificates');
    }

    /**
     * 获取某个Provisioning devices详情
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function listAllDevicesInProfile($id, array $query = []){
        return $this->curlGet('/profiles/' . $id . '/devices');
    }

    /**
     * 获取某个Provisioning 相关的 devices详情
     * @param $id
     * @param array $query
     * @return array|mixed
     */
    public function getAllDeviceResourceIDsInProfile($id, array $query = []){
        return $this->curlGet('/profiles/' . $id . '/relationships/devices');
    }


    public function getCertificateSigningRequest($commonName, $emailAddress)
    {
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

    /**
     * 查找最新adhoc的证书。
     * @param string $type
     * @return array
     */
    public function listLatestCertificates($type = 'IOS_DISTRIBUTION'){
        $rets = $this->curlGet('/certificates');
        $info = [];
        if(isset($rets['data'])) foreach ($rets['data'] as $k=>$row){
            if($type == $row['attributes']['certificateType']){
                if($info) { //如果有数据，则比较时间
                    if(strtotime($info['attributes']['expirationDate'])<strtotime($row['attributes']['expirationDate'])) {
                        $info = $row;
                    }
                }else{
                    $info = $row;
                }
            }
        }
        return $info;
    }

    /**
     *
    array(4) {
        ["type"]=>
        string(12) "certificates"
        ["id"]=>
        string(10) "MYT2V6955Y"
        ["attributes"]=>
            array(8) {
            ["serialNumber"]=>
            string(16) "60A00CA774CD5807"
            ["certificateContent"]=>
            string(1908) "MIIFkTCCBHmgAwIBAgIIYKAMp3TNWAcwDQYJKoZIhvcNAQELBQAwgZYxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjAwNjE1MDMzODU5WhcNMjEwNjE1MDMzODU5WjCBhDEaMBgGCgmSJomT8ixkAQEMClA4NjlNVDVKWEYxMjAwBgNVBAMMKWlQaG9uZSBEaXN0cmlidXRpb246IEZlbmcgWWUgKFA4NjlNVDVKWEYpMRMwEQYDVQQLDApQODY5TVQ1SlhGMRAwDgYDVQQKDAdGZW5nIFllMQswCQYDVQQGEwJDTjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOxtKJOZktRshHbdrBTlsVvFsTGX/TqvTW8fk9MiXK0iMMwpkG5J8mCcPj1qY9opZi5RMkmutdcVxdfRKlZ4MZ2nw0KIs2ZyI5PeBOdQU+rI7jSbbd/f83VevWSfkGKAtX8sHjnoJ4oIJg0oqb963YHOsrAyO7F4hebyY9NXheD7DzepJtJtWiFTF8iH12dag3IA2QNxTEzJxLtzWkhdm0oP2VZBEqas5Yhe0Iq+kDKyppgQniZx3nvDv6Dk5x7HtLe6mrnW9b725k+WaZMt6IRswPEnNiB5ok0k3ZDyxs0zSo1XhKk6f8W/cnTGk9JYzZsKRBVgTSQf+OEI7Twd6E8CAwEAAaOCAfEwggHtMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUiCcXCam2GGCL7Ou69kdZxVJUo7cwPwYIKwYBBQUHAQEEMzAxMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLXd3ZHIxMTCCAR0GA1UdIASCARQwggEQMIIBDAYJKoZIhvdjZAUBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFN0lN/ejqETv8PJqebKSYHzLkRZAMA4GA1UdDwEB/wQEAwIHgDATBgoqhkiG92NkBgEEAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEApOZtAVdIaF7lmrEt+ZXGxrrH1NVoZRjRUC8pWb9ih1WWI5etgcbwq+EuZefNNBuMKv+MChHy6XBpMiM9t0AkAwC1iWAqeqi7ze/5T96j0alrjEFw7ytLQ5BRxdGLFbeuoX+IznuIw+sxJr8pDC68vVzhh/kkIE+CeCciAR8pVBdw5lb5zHY504AaXIVTY5pDV5IaNHzzjqOdmQGE3ELHaqyRrnuWOa9FauhGnvs1lqJVbflOuQwKxfQBLO+dOy8X/nJ0GVboE6ueCpynFWVoVSZj/TuPP2lVODsImT9dYgVxnXwTYQrEQ5/gaEeBb7Xw8tsy/R5nJMW6WTUCnkBrfA=="
            ["displayName"]=>
            string(7) "Feng Ye"
            ["name"]=>
            string(25) "iOS Distribution: Feng Ye"
            ["csrContent"]=>
            NULL
            ["platform"]=>
            string(3) "IOS"
            ["expirationDate"]=>
            string(28) "2021-06-15T03:38:59.000+0000"
            ["certificateType"]=>
            string(16) "IOS_DISTRIBUTION"
        }
        ["links"]=>
        array(1) {
        ["self"]=>
        string(64) "https://api.appstoreconnect.apple.com/v1/certificates/MYT2V6955Y"
        }
    }
     * 列出所有的证书
     * @return array|mixed
     */
    public function listAllCertificates(){
        return  $this->curlGet('/certificates');
    }

    /**
     * 获取指定类型的证书,用于统计数量，超出可以删除。
     * @return array|mixed
     */
    public function showTypeCertificates($type = 'IOS_DISTRIBUTION'){
        $rets = $this->curlGet('/certificates');
        $info = [];
        if (isset($rets['data'])) foreach ($rets['data'] as $k => $row) {
            if ($type == $row['attributes']['certificateType']) {
                $info[] = $row;
            }
        }
        return $info;
    }

    /**
     * 销毁某一个证书
     * @param $id
     * @return mixed
     */
    public function revokeCertificate($id){
        $ret = $this->curlDel('/certificates/' . $id);
        return isset($ret['errors']) ? false : true;
    }

    /**
     * 创建某一个证书。
     *
     *
    array(2) {
        ["data"]=>
        array(4) {
        ["type"]=>
        string(12) "certificates"
        ["id"]=>
        string(10) "FPFFT7ZAFW"
        ["attributes"]=>
            array(8) {
            ["serialNumber"]=>
            string(16) "772838EC71E04854"
            ["certificateContent"]=>
            string(1908) "MIIFkTCCBHmgAwIBAgIIdyg47HHgSFQwDQYJKoZIhvcNAQELBQAwgZYxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjAwNjE2MTM0NjQ1WhcNMjEwNjE2MTM0NjQ1WjCBhDEaMBgGCgmSJomT8ixkAQEMClA4NjlNVDVKWEYxMjAwBgNVBAMMKWlQaG9uZSBEaXN0cmlidXRpb246IEZlbmcgWWUgKFA4NjlNVDVKWEYpMRMwEQYDVQQLDApQODY5TVQ1SlhGMRAwDgYDVQQKDAdGZW5nIFllMQswCQYDVQQGEwJDTjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM8ak8hfmO4a+/WRzofg6IrrogXpHraDIoNQ+NhDBJNNfRUB7EyhqjhaCrLn6KCJMeR6a3T5GODPOoPXRxamQ3udqLkNsxSjDsyPuFPjyOhjYI6OakeBRRq2SLUAjBRwqMbTuEOlgMcgkE7ci86326Xj+lr7MUowOlWECIFgoFMNp1RZK4sFEpmnCme9HPd0Bg8INZ7QcFjF/M7jzMfUCnLtj1tbcyXkEq0v/gtztZqndgJ1LQjXSiqPSuduxJiNqjihXZKk/+ROcGm5bT0FFYeHIn3qhWzxD857i0R/Z4jmWlCXGwp+cD9fo+G3iSHtTPwebtvwehjMrnDLvhmEA48CAwEAAaOCAfEwggHtMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUiCcXCam2GGCL7Ou69kdZxVJUo7cwPwYIKwYBBQUHAQEEMzAxMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLXd3ZHIxMTCCAR0GA1UdIASCARQwggEQMIIBDAYJKoZIhvdjZAUBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFOq5m9iuslOeU6R9i9v4DL0mI2zNMA4GA1UdDwEB/wQEAwIHgDATBgoqhkiG92NkBgEEAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAM2eENMaaiUJsNqMRJyJH1ziC7ZYr53DnbNzQggoWTDEQ99UuFBt0ebnhAa8ADjDe54w20oJRm0IRB6RVQhQyjhTBaEASBTnrujBXD1MhongF3WI0P7AJDZBk7SGycX1hKV+tzDtB2CgghMTl0T0qKihVF9ClSLZhrEkLpLloQJn8fWASCM6bUgZGU7lUtQxFRrubDoBPXTVnLnTUZ5nRarj40K0P0KH9ublLi6sCQrq2issARE1dzRTIf9gYnnCUp75gTEAULmQCg1/Z1lUVRiuhPnJHd7EqRxs9SLfV77brpf/I3KtzHpStL785LoibzILxXsmi1Lci+GkA4RTNRg=="
            ["displayName"]=>
            string(7) "Feng Ye"
            ["name"]=>
            string(25) "iOS Distribution: Feng Ye"
            ["csrContent"]=>
            NULL
            ["platform"]=>
            string(3) "IOS"
            ["expirationDate"]=>
            string(28) "2021-06-16T13:46:45.000+0000"
            ["certificateType"]=>
            string(16) "IOS_DISTRIBUTION"
            }
            ["links"]=>
            array(1) {
            ["self"]=>
            string(64) "https://api.appstoreconnect.apple.com/v1/certificates/FPFFT7ZAFW"
            }
        }
        ["links"]=>
        array(1) {
        ["self"]=>
        string(53) "https://api.appstoreconnect.apple.com/v1/certificates"
        }
    }

     *
     * 创建指定类型证书。
     * @param $certificateType Possible values: IOS_DEVELOPMENT, IOS_DISTRIBUTION, MAC_APP_DISTRIBUTION,
     * MAC_INSTALLER_DISTRIBUTION, MAC_APP_DEVELOPMENT, DEVELOPER_ID_KEXT, DEVELOPER_ID_APPLICATION
     * @param $csrContent
     * @return mixed|string
     *
     *
     */
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
        return $this->curlPost('/certificates',$params);
    }

    /**
     * 读取某一个证书的信息。
     * @param $id
     * @param array $query
     * @return mixed
     */
    public function readCertificateInformation($id, array $query = []){
        return $this->curlGet('/certificates/'.$id,$query);
    }




    public function getPlist($url,$bundle,$version,$name,$path){
        $str = '<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
            <dict>
                <key>items</key>
                <array>
                    <dict>
                        <key>assets</key>
                        <array>
                            <dict>
                                <key>kind</key>
                                <string>software-package</string>
                                <key>url</key>
                                <string>' . $url . '</string>
                            </dict>
                        </array>
                        <key>metadata</key>
                        <dict>
                            <key>bundle-identifier</key>
                            <string>' . $bundle . '</string>
                            <key>bundle-version</key>
                            <string>' . $version . '</string>
                            <key>kind</key>
                            <string>software</string>
                            <key>title</key>
                            <string>' . $name . '</string>
                        </dict>
                    </dict>
                </array>
            </dict>
        </plist>';
        $filename = $path . $this->acc . '.plist';
        file_put_contents($filename,$str);
        // if (!file_exists($filename)) {
        //     $myfile = fopen($filename, "w") or die("Unable to open file!");
        //     fwrite($myfile, $str);
        //     fclose($myfile);
        // }
        return $filename;
    }





}