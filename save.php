<?php 

include_once "class.alphapad.php";
//- (1) We 1st set user data and the system
$system_pad = 300;
$system_key = 90;
$permutation = new alphaPad($system_key,$system_pad); $my_id = "john smith"; //- The owner id provided by the system 
$my_id = $permutation->_encrypt($my_id); //- your identity is now set private by encryption

$data = $my_id."_movie_name_".time();
$saved_file = $my_id."/".$data.".torrent"; //- the original document to protect
chmod($saved_file,600); //- to make sure nobody except the owner can access it
 
$trusted_ids = $my_id."/".$my_id."-list.txt"; //- and create a list of trusted people
$cmd = "grep '".$my_id."' ".$trusted_ids." > result-".$my_id.".out"; exec($cmd);
if (filesize("result-".$my_id.".out") == 0) file_put_contents($trusted_ids, $my_id."\n"); //- starting by the owner himself
chmod($saved_file,600);

$my_hash = sha1($data);
$data_string = serialize(array("hash" => $my_hash,"alpha_pad_id" => $my_id)); $fhash = sha1($data_string);

//- (2) Then request a timestamp using OpenSSL and capture the response
// The request is HTTP POST binary data in the header that is passed to the server using curl. You'll need to have a bit of info for this:
//  URL - An RFC3161 time-stamping service (DFN-Verein in our case)
//  FHASH - The final hash (set up earlier) you want a timestamp for. Must be a full hash.
$cmd0 = '
CONTENT_TYPE="Content-Type: application/timestamp-query"
ACCEPT_TYPE="Accept: application/timestamp-reply"
URL = "http://zeitstempel.dfn.de" ';
exec($cmd0);

$cmd1 = 'openssl ts -query -cert -digest '.escapeshellarg($fhash).' -sha1 \
    | curl -s -S -H "$CONTENT_TYPE" -H "$ACCEPT_TYPE" --data-binary @- "$URL" -o response.tsr ';

//- What $cmd1 does is the following: we create a time stamp request
//- The output is a time stamp request that contains the SHA1 hash value of your data; ready to be sent to the TSA (DFN-Verein in our case - see the bottom of the article for more TSA).
//- Then after the "|" in the command,i.e once the request is ready, the curl program transmits your request to the DFN-Verein servers.
//- If an error occurs then the output file will contain information to help debug (see the parameter -S in the command).
//- Otherwise the output file (.tsr file) is the RFC3161 timestamp response of your file is returned

exec($cmd1." 2>&1", $array, $status);
if ($status !== 0) throw new Exception("OpenSSL does not seem to be installed: ".implode(", ", $array));
if (stripos($array[0], "openssl:Error") !== false) throw new Exception("There was an error with OpenSSL. Is version >= 0.99 installed?: ".implode(", ", $retarray));

//- (3) We now verify the response by extracting the timestamp and if valid, we save that response string/token

$cmd2 = "openssl ts -reply -in response.tsr -text";
$timestamp_response_array = execute_reply($cmd2, $my_id."_".$my_hash);
$matches = array();
$response_time = 0;
foreach ($timestamp_response_array as $retline){
  if (preg_match("~^Time\sstamp\:\s(.*)~", $retline, $matches)){
            $response_time = strtotime($matches[1]);
            break;   
  }
}

if (!$response_time)throw new Exception("The Timestamp was not found");
echo "File and identity saved, safe and sound! \n
           Here are the credentials for your trusted peers:\n
           hashID:".$my_id."\n
           hashTorrent: ".$my_hash;

function execute_reply($command, $storage_name) {
    $retarray = array();
    exec($command." 2>&1", $retarray, $retcode);

    if ($retcode !== 0) throw new Exception("The reply failed: ".implode(", ", $retarray));
    else {
        //- We gather the response token in a file for future authentications
        $tmpfname = tempnam("/responses", $storage_name); //- tempnam will chmod the file to 600 i.e unalterable except by the owner of the file
        $save_cmd = "echo '".$command."' > ".$tmpfname."";
        unlink("request.tsq"); unlink ("response.tsr");
    }
    return $retarray;
}
