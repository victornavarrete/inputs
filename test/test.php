<?php

require '../src/Inputs.php';

$example_text = 'Hi world';

$inputs = new Inputs();

$out['origin'] = $inputs->origin();
$out['user_agent'] = $inputs->user_agent();
$out['protocol'] = $inputs->protocol();
$out['method'] = $inputs->method();
$out['is_http_secure'] = $inputs->is_http_secure();
$out['ip_address'] = $inputs->ip_address(); 
$out['current_url'] = $inputs->current_url(); 
$out['request_header'] = $inputs->request_header();  
$out['is_ajax_request'] = $inputs->is_ajax_request();
$out['is_cli_request'] = $inputs->is_cli_request();
$out['is_origin_request'] = $inputs->is_origin_request();
$out['get'] = $inputs->get();
$out['post'] = $inputs->post();
$out['put'] = $inputs->put();
$out['delete'] = $inputs->delete();
$out['patch'] = $inputs->patch(); 
$out['input_stream'] = $inputs->input_stream(); 

header('Content-type: application/json');
echo json_encode($out,JSON_PRETTY_PRINT );