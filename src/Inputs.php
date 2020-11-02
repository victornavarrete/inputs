<?php  
 

Class Inputs { 

    private $_headers = []; 
  
    public $encrypt_method = 'aes-256-cbc';  
    public $encrypt_key = 'MySecP2020'; 

    public $anti_xss = null;  

    public $filename_bad_chars =	array(
		'../', '<!--', '-->', '<', '>',
		"'", '"', '&', '$', '#',
		'{', '}', '[', ']', '=',
		';', '?', '%20', '%22',
		'%3c',		// <
		'%253c',	// <
		'%3e',		// >
		'%0e',		// >
		'%28',		// (
		'%29',		// )
		'%2528',	// (
		'%26',		// &
		'%24',		// $
		'%3f',		// ?
		'%3b',		// ;
		'%3d'		// =
	);

    function __construct() {       
        if (class_exists('AntiXSS')) {
            $this->anti_xss = new AntiXSS(); 
        }
        $this->_set_request_header();   
    }

    private function _fetch_from_array(&$array, $index, $xss_clean = true)
    {  
        isset($index) OR $index = @array_keys($array);  

        if (is_array($index))
        {
            $output = array();
            foreach ($index as $key)
            {
                $output[$key] = $this->_fetch_from_array($array, $key, $xss_clean);
            } 
            return $output;
        } 
        if (isset($array[$index]))
        {
            $value = $array[$index];
        }
        elseif (($count = preg_match_all('/(?:^[^\[]+)|\[[^]]*\]/', $index, $matches)) > 1)  
        {
            $value = $array;
            for ($i = 0; $i < $count; $i++)
            {
                $key = trim($matches[0][$i], '[]');
                if ($key === '')  
                {
                    break;
                }

                if (isset($value[$key]))
                {
                    $value = $value[$key];
                }
                else
                {
                    return NULL;
                }
            }
        }
        else
        {
            return NULL;
        } 
        return ($xss_clean === TRUE) ? $this->xss_clean($value) : $value;
    }

    private function _set_request_header(){   
        $headers = function_exists('apache_request_headers')?apache_request_headers():getallheaders(); 
        $this->_headers = [];
        foreach ($headers as $k => $v) {    
            $k = str_replace('_', ' ', strtolower($k));
            $k = str_replace(' ', '-', $k); 
            $this->_headers[$k] = $v; 
        }    
    }  

    public function input_stream($xss_clean = true){  
       $value = (string) file_get_contents('php://input','r');  
	   return ($xss_clean === TRUE) ? $this->xss_clean($value) : $value;
    }

    public function input_json($xss_clean = true){   
       return json_decode($this->input_stream($value));
    }  

    public function request_header($index=null, $xss_clean = true){   
        if(is_string($index)){
            $index= strtolower($index);
        }
        return  $this->_fetch_from_array($this->_headers, $index, $xss_clean);
    } 

    public function server($index =null, $xss_clean = true){
		return $this->_fetch_from_array($_SERVER, $index, $xss_clean);
	}

	public function get($index =null, $xss_clean = true){
		return $this->_fetch_from_array($_GET, $index, $xss_clean);
    }
    
	public function post($index =null, $xss_clean = true){
		return $this->_fetch_from_array($_POST, $index, $xss_clean);
    } 

    // rest  
    public function _from_stream($index =null, $xss_clean = true){ 
        $stream = $this->input_stream($xss_clean); 
        parse_str($stream,$vars);
        return ($vars[$index])?$vars[$index]:$vars;
    }

	public function put($index =null, $xss_clean = true){ 
        if(!$this->is_method('put')){ return null; }
		return $this->_from_stream( $index, $xss_clean);  
	}

	public function delete($index =null, $xss_clean = true){
        if(!$this->is_method('delete')){ return null; }
		return $this->_from_stream( $index, $xss_clean);  
	}

	public function patch($index =null, $xss_clean = true){
        if(!$this->is_method('patch')){ return null; }
        return $this->_from_stream( $index, $xss_clean);  
    }

    public function post_get($index =null, $xss_clean = true){
		return isset($_POST[$index]) ? $this->post($index, $xss_clean) : $this->get($index, $xss_clean);
	} 
 
	public function get_post($index =null, $xss_clean = true){
		return isset($_GET[$index]) ? $this->get($index, $xss_clean) : $this->post($index, $xss_clean);
    }  
  
    public function origin( ){
        return $this->server('HTTP_ORIGIN', false);
    }  

    public function current_url(){
        $protocol = $this->protocol();   
        return  $protocol.'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']; 
    }

    public function server_name( ){
		return $this->server('SERVER_NAME', false);
    }  
    
    public function is_origin_request($all_methods=false){ 
        $origin = $this->origin(); 
        $protocol = $this->protocol();   
        if ($this->is_method('post') || $all_methods ) { 
            if (isset($origin)) { 
                $address = $protocol.'://'.$_SERVER['SERVER_NAME'];
                if (strpos($address, $origin) !== 0) {
                    return false;
                }
                return true;
            }
        } 
        return null;
    }
    
    public function user_agent(){
		return $this->server('HTTP_USER_AGENT',true);
    }  

    public function method( ){
        return  strtoupper($_SERVER['REQUEST_METHOD']);
    }

    public function is_method($keyname){
		return (strtoupper($keyname) == $this->method());
    }

    public function protocol( ){ 
        $p = ($this->is_http_secure())?'https':'http';
        return  $p;
    }
 
    public function is_http_secure(){ 
        if ( ! empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
        {
            return TRUE;
        }
        elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
        {
            return TRUE;
        }
        elseif ( ! empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off')
        {
            return TRUE;
        }

        return FALSE;
    }

    public function valid_ip($ip, $which = ''){
        switch (strtolower($which))
        {
            case 'ipv4':
                $which = FILTER_FLAG_IPV4;
                break;
            case 'ipv6':
                $which = FILTER_FLAG_IPV6;
                break;
            default:
                $which = NULL;
                break;
        }

        return (bool) filter_var($ip, FILTER_VALIDATE_IP, $which);
    }  

    public function ip_address($from_remote=true){  
        $ip = ($from_remote)?$_SERVER['REMOTE_ADDR']:$_SERVER['HTTP_X_FORWARDED_FOR']; 
        if (!$this->valid_ip($ip)){
            return $ip = '0.0.0.0';
        }

        return $ip;
    } 

    public function is_ajax_request(){
		return ( ! empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
    }
    
    public function is_cli_request(){
		return (PHP_SAPI === 'cli' OR defined('STDIN'));
    }

   

    /// EXTRAS 

    public function encrypt($data) { 
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->encrypt_method));
        $encrypted=openssl_encrypt($data, $this->encrypt_method, $this->encrypt_key, 0, $iv); 
        return base64_encode($encrypted."::".$iv);

    }

    public function decrypt($data) { 
        list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
        return openssl_decrypt($encrypted_data, $this->encrypt_method, $this->encrypt_key, 0, $iv);
    }


    public function strip_image_tags($str){
		return preg_replace(
			array(
				'#<img[\s/]+.*?src\s*=\s*(["\'])([^\\1]+?)\\1.*?\>#i',
				'#<img[\s/]+.*?src\s*=\s*?(([^\s"\'=<>`]+)).*?\>#i'
			),
			'\\2',
			$str
		);
	}

    public function remove_invisible_chars($str, $url_encoded = TRUE){
		$non_displayables = array(); 
		// every control character except newline (dec 10),
		// carriage return (dec 13) and horizontal tab (dec 09)
		if ($url_encoded)
		{
			$non_displayables[] = '/%0[0-8bcef]/i';	// url encoded 00-08, 11, 12, 14, 15
			$non_displayables[] = '/%1[0-9a-f]/i';	// url encoded 16-31
			$non_displayables[] = '/%7f/i';	// url encoded 127
		}

		$non_displayables[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';	// 00-08, 11, 12, 14-31, 127

		do
		{
			$str = preg_replace($non_displayables, '', $str, -1, $count);
		}
		while ($count);

		return $str;
    } 
    
    public function sanitize_filename($str, $relative_path = FALSE){
		$bad = $this->filename_bad_chars;

		if ( ! $relative_path)
		{
			$bad[] = './';
			$bad[] = '/';
		}

		$str = $this->remove_invisible_chars($str, FALSE);

		do
		{
			$old = $str;
			$str = str_replace($bad, '', $str);
		}
		while ($old !== $str);

		return stripslashes($str);
    }
 

    public function xss_clean($data){

        if($this->anti_xss){
              return  $this->anti_xss->xss_clean($data);
        }

        // Fix &entity\n;
        $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
        $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
        $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
        $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

        // Remove any attribute starting with "on" or xmlns
        $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

        // Remove javascript: and vbscript: protocols
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

        // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

        // Remove namespaced elements (we do not need them)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

        do
        {
                // Remove really unwanted tags
                $old_data = $data;
                $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
        }
        while ($old_data !== $data);

        // we are done...
        return $data;
    }
    

}
 