<?php
$config['redis'] = array(
    'host'=>'0.0.0.0', //连接地址
    'port'=>'6379',//连接端口
    'auth'=>'123456',// 连接密码
    'method'=>'pconnect', //连接方式 pconnect 长连接；connect 短连接
    'timeout'=>1000, //长持续连接时间秒为单位
);

/**
*  redisdrive.class.php
* php redis 操作类
**/
class Redisv{
    public $valid_drivers;
    public $CI;
    /**
     * 自动连接到redis缓存
     */

    public function __construct(){
        //判断php是否支持redis扩展
        if(extension_loaded('redis')){
            //实例化redis 
            //加载config redis配置
            // $this->_ci=get_instance();
            if($this->redis = new redis()){
                // 验证是否有配置没有使用默认的
                // if(!isset($config)){
                //    $config = $this->_ci->config->item('redis');
                // }
                //ping连接
                if($config['method'] == 'pconnect'){
                   $res =  $this->redis->pconnect($config['host'],$config['port'],$config['timeout']);
                }else{
                    $res =  $this->redis->connect($config['host'],$config['port']);
                }
                if($res){
                    // 验证
                    if(isset($config['auth'])){
                        if(!$this->redis->auth($config['auth'])){
                            return false;
                        }
                    }
                    return true;
                }else{
                   return false;
                }
            }else{
                $this->redis = false;
            }
        }else{
            $this->redis = false;
        }
    }
    // 修改私有属性的值
    public function set_param($name,$value){
        $this->$name = $value;
    }
    /**
     * 检测redis键是否存在
     */
    public function exists($key){
        if($this->redis->exists($key)){
            return true;
        }else{
            return false;
        }
    }
 
    /**
    * 获取redis键的值
    */
    public function get($key){
        if($this->redis->get($key)){
            return json_decode($this->redis->get($key),true);
        }else{
            return false;
        }
    }
    /**
    * 带生存时间写入key
    */
    public function set($key,$value,$expire=800000){
             //加载config redis配置
        if($expire>0){
             return $this->redis->setex($key,$expire,$value);
        }else{
            return $this->redis->set($key,$expire);
        }
    }
 
     /**
      * 获取key生存时间
      */
    public function ttl($key){
         return $this->redis->ttl($key);
    }
 
    /**
     *删除key
     */
    public function del($key){
        return $this->redis->del($key);
    }

    /**
     * List(列表)  写入
     */
    public function lpush($key,$value){
        return $this->redis->lpush($key);
    }


   /**
     * 发送事件
     */
    public function publish($key,$value){
        return $this->redis->publish($key,$value);
    }


    /**
     * List(列表)  获取
     */
    public function lrange($key,$start,$end){
        if($this->exists($key)){
           return $this->redis->lrange($key,$start,$end);
        }else{
            return false;
        }
    }

 
   /**
     * 清空所有数据
     */
    public function flushall(){
        return $this->redis->flushall();
    }
    /**
    * 获取所有key
    */
    public function keys(){
        return $this->redis->keys('*');
    }
 


    // #获取hash指定字段的值
    // $redis->hget('hash','a');
    // #批量获取
    // $redis->hmget('hash',['a','b','c']);
    // #获取全部
    // $redis->hgetall('hash');
    // #获取hash表中所有字段的值
    // $redis->hvals('hash');
    // #获取hash表中所有的字段
    // $redis->hkeys('hash');

    /**
    * 获取hash所有内容
    */
    public function hsgetall($key){
        return $this->redis->hgetall($key);
    }

    /**
    * 获取hash指定字段的值
    */
    public function hsget($key,$key2){
        return $this->redis->hget($key,$key2);
    }
 

}