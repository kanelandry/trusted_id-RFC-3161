<?php 

include_once "class.alphapad.php";
$system_pad = 300;
$system_key = 90;
$permutation = new alphaPad($system_key,$system_pad);

$user_id = "carla joe"; //- user who is trying to access file T 
$user_id = $permutation->_encrypt($user_id);

$provided_id = 12232323434439999; //- should be the same as $my_id for the authentication to work
$provided_hash = "e47b8eef9eb2bedca76dcdd4041d3e1755e2324a"; //- should be the same as $my_hash for the authentication to work
 
$user_string = serialize(array("hash" => $provided_hash,"alpha_pad_id" => $provided_id)); $user_hash = sha1($user_string);

$response_token = $provided_id."_".$provided_hash;
$file_timestamp = $response_time; //- we suppose it has been saved in the system after the process in the precedent section
$tsa_cert_chain_file = "chain.txt"; //- the certificate chain from the TSA of our system
$trusted_ids = $provided_id."/".$provided_id."-list.txt";

if (file_exists($trusted_ids)){
    $cmd = "grep '".$user_id."' ".$trusted_ids." > result-".$provided_id."-".$user_id.".out";         
    exec($cmd);
   
    if (filesize("result-".$provided_id."-".$user_id.".out") == 0) {
       $validated = validate($user_hash, $response_token, $file_timestamp, $tsa_cert_chain_file, $user_id);
       if ($validated == 1) {
            file_put_contents($trusted_ids, $user_id."\n");
            echo "You're in!";
        }
        else throw new Exception( "Hash mismatch! Please try again");
        //- var_dump($validated);
    }
    else echo "You're in!";
}
else {
     error_log_type(1, $user_id);
     throw new Exception("The file you are trying to access doesn't exist");   
}

function validate ($hash, $response_token, $response_time, $tsa_cert_file, $user) {
   
    if (strlen($hash) !== 40) {
         error_log_type(1, $user, "Provided file's hash");
         throw new Exception("Invalid Hash");
    }
    $response_file = './responses/'.$response_token;
    if (!file_exists($response_file)) {
        error_log_type(1, $user, "Name of the response token");
        throw new Exception("Invalid Hash or owner ID");
    }
    if (!intval($response_time)){
        error_log_type(1, $user, "Provided timestamp");
        throw new Exception("There is no valid response-time given");
    }
    if (!file_exists($tsa_cert_file)) {
        error_log_type(1, $user, "Path to the certiificate chain");
        throw new Exception("The TSA-Certificate could not be found");
    }

 $cmd = "openssl ts -verify -digest ".escapeshellarg($hash)." -in ".escapeshellarg($response_file)." -CAfile ".escapeshellarg($tsa_cert_file);
   
$array = array();
exec($cmd." 2>&1", $array, $status);
  
    if ($status === 0 && strtolower(trim($array[0])) == "verification: ok")
       return 1;

    foreach ($array as $rline)
    {
        if (stripos($line, "message imprint mismatch") !== false)
           {error_log_type(2, $user, "Provided file's hash"); return 0;}
    }
   
    error_log_type(3, $user, implode(", ", $array));
    throw new Exception("System command failed: ".implode(", ", $array));
}

function error_log_type($severity, $user, $parameter){
    date_default_timezone_set('UTC');
    $log_file = "./error.log";
    switch ($severity){    
        case(1): $error = "Wrong information provided";break;
        case(2): $error = "Hash's print match failed";break;
        case(3): $error = "Fatal error - System command failed";break;
    }
    $error = "[ ".date('l jS \of F Y h:i:s A')." ] - ".$error." - [ Author: ".$user.", Parameter: ".$parameter."] \n";
    file_put_contents($log_file, $error);
}
