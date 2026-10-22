<?php
/** Isolated update fixtures: no network or site configuration is accessed. */
define('ABSPATH',sys_get_temp_dir().'/');define('IP_BLOCKER_WAF_VERSION','0.1.2');define('IP_BLOCKER_WAF_FILE','ip-blocker-with-waf/ip-blocker-with-waf.php');define('HOUR_IN_SECONDS',3600);define('MINUTE_IN_SECONDS',60);
class WP_Error{private $code;public function __construct($c,$m=''){$this->code=$c;}public function get_error_code(){return $this->code;}}
function is_wp_error($v){return $v instanceof WP_Error;}function __($v,$d=''){return $v;}function esc_html__($v,$d=''){return htmlspecialchars($v,ENT_QUOTES);}function esc_url($v){return htmlspecialchars($v,ENT_QUOTES);}function plugin_basename($v){return $v;}
$cache=false;$calls=array();$http=null;$ttls=array();$files=array();$checks=0;
function get_site_transient($k){global $cache;return $cache;}function set_site_transient($k,$v,$ttl){global $cache,$ttls;$cache=$v;$ttls[]=$ttl;}
function wp_safe_remote_get($url,$args){global $http,$calls;$calls[]=array($url,$args);return $http($url,$args);}function wp_remote_retrieve_response_code($r){return $r['code'];}function wp_remote_retrieve_body($r){return $r['body'];}
function wp_tempnam($n){global $files;$p=tempnam(sys_get_temp_dir(),'ipbw-updater-');$files[]=$p;return $p;}function wp_delete_file($p){if(is_file($p))unlink($p);}
require dirname(__DIR__).'/wordpress-plugin/includes/class-updater.php';
function verify($ok,$label){global $checks;++$checks;if(!$ok)throw new RuntimeException('FAIL: '.$label);}
function fixture($tag='v0.1.3'){$r=IP_Blocker_WAF_Updater::REPO;return array('tag_name'=>$tag,'draft'=>false,'prerelease'=>false,'html_url'=>$r.'/releases/tag/'.$tag,'assets'=>array(array('name'=>'ip-blocker-with-waf.zip','browser_download_url'=>$r.'/releases/download/'.$tag.'/ip-blocker-with-waf.zip'),array('name'=>'ip-blocker-with-waf.zip.sha256','browser_download_url'=>$r.'/releases/download/'.$tag.'/ip-blocker-with-waf.zip.sha256')));}
function response($body,$code=200){return array('body'=>$body,'code'=>$code);}
try{
 $good=fixture();verify(IP_Blocker_WAF_Updater::parse_release($good)['version']==='0.1.3','stable release');
 foreach(array('draft','prerelease')as$key){$bad=$good;$bad[$key]=true;verify(false===IP_Blocker_WAF_Updater::parse_release($bad),'non-stable rejected');}
 foreach(array('v1.2.3-rc1','v01.2.3','v1.2','v1.2.3?')as$tag)verify(false===IP_Blocker_WAF_Updater::parse_release(fixture($tag)),'invalid version');
 foreach(array('https://evil.invalid/a.zip',str_replace('https:','http:',$good['assets'][0]['browser_download_url']),$good['assets'][0]['browser_download_url'].'?x=1',str_replace('v0.1.3','v9.9.9',$good['assets'][0]['browser_download_url']))as$url){$bad=$good;$bad['assets'][0]['browser_download_url']=$url;verify(false===IP_Blocker_WAF_Updater::parse_release($bad),'foreign or mismatched asset');}
 $bad=$good;array_pop($bad['assets']);verify(false===IP_Blocker_WAF_Updater::parse_release($bad),'checksum required');
 $bad=$good;$bad['assets'][]=$bad['assets'][0];verify(false===IP_Blocker_WAF_Updater::parse_release($bad),'duplicate rejected');
 $bad=$good;$bad['html_url']='https://evil.invalid/';verify(false===IP_Blocker_WAF_Updater::parse_release($bad),'release page validated');
 $http=static function(){return response(json_encode(fixture()));};
 verify('keep'===IP_Blocker_WAF_Updater::update('keep',array(),'other.php',array())&&count($calls)===0,'other plugins untouched');
 $result=IP_Blocker_WAF_Updater::update(false,array(),IP_BLOCKER_WAF_FILE,array());verify($result['version']==='0.1.3'&&$result['autoupdate']===false,'WordPress update metadata');
 verify($ttls[0]===21600&&count($calls)===1,'six hour positive cache');IP_Blocker_WAF_Updater::update(false,array(),IP_BLOCKER_WAF_FILE,array());verify(count($calls)===1,'cached requests');
 $a=$calls[0][1];verify($a['sslverify']&&$a['user-agent']==='IP-Blocker-With-WAF/0.1.2'&&!isset($a['cookies']),'TLS and non-identifying user agent');
 $info=IP_Blocker_WAF_Updater::information(false,'plugin_information',(object)array('slug'=>'ip-blocker-with-waf'));verify($info->version==='0.1.3'&&strpos($info->sections['changelog'],IP_Blocker_WAF_Updater::REPO)!==false,'plugin information modal');
 $cache=IP_Blocker_WAF_Updater::parse_release(fixture('v0.1.2'));verify(false===IP_Blocker_WAF_Updater::update(false,array(),IP_BLOCKER_WAF_FILE,array()),'same version ignored');
 $cache=false;$http=static function(){return new WP_Error('offline');};verify(false===IP_Blocker_WAF_Updater::update(false,array(),IP_BLOCKER_WAF_FILE,array())&&end($ttls)===900,'fifteen minute failure cache');
 $package=$good['assets'][0]['browser_download_url'];$n=count($calls);verify('keep'===IP_Blocker_WAF_Updater::download('keep',$package,null,array()),'previous reply preserved');verify(false===IP_Blocker_WAF_Updater::download(false,'https://example.invalid/a.zip',null,array())&&count($calls)===$n,'unrelated downloads untouched');
 $http=static function(){return response('invalid');};$r=IP_Blocker_WAF_Updater::download(false,$package,null,array());verify(is_wp_error($r)&&$r->get_error_code()==='ipbw_checksum_unavailable','checksum fails closed');
 $payload='inert-package-fixture';$digest=hash('sha256',$payload);
 $http=static function($url,$a)use($payload,$digest){if(substr($url,-7)==='.sha256')return response($digest.'  ip-blocker-with-waf.zip');file_put_contents($a['filename'],$payload);return response('');};
 $p=IP_Blocker_WAF_Updater::download(false,$package,null,array());verify(is_string($p)&&file_get_contents($p)===$payload,'verified streamed file');wp_delete_file($p);
 $http=static function($url,$a)use($digest){if(substr($url,-7)==='.sha256')return response($digest.'  ip-blocker-with-waf.zip');file_put_contents($a['filename'],'tampered');return response('');};
 $r=IP_Blocker_WAF_Updater::download(false,$package,null,array());verify(is_wp_error($r)&&$r->get_error_code()==='ipbw_checksum_mismatch'&&!is_file(end($files)),'tampered file rejected and cleaned');
 $http=static function(){return response(str_repeat('a',64).'  wrong.zip');};$r=IP_Blocker_WAF_Updater::download(false,$package,null,array());verify(is_wp_error($r)&&$r->get_error_code()==='ipbw_checksum_unavailable','checksum filename validated');
 echo 'PASS '.$checks.' GitHub updater checks'.PHP_EOL;
}finally{foreach($files as$p)wp_delete_file($p);}
