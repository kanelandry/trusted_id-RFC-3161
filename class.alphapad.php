<?php

class alphaPad {
        
        private $key = 0;
        private $padding_par = 0;
        private $alphabet = array(
        "00"=>" ", "01"=>"a","02"=>"b","03"=>"c","04"=>"d","05"=>"e","06"=>"f","07"=>"g","08"=>"h","09"=>"i",
        "10"=>"j","11"=>"k","12"=>"l","13"=>"m","14"=>"n","15"=>"o","16"=>"p","17"=>"q","18"=>"r","19"=>"s",
        "20"=>"t","21"=>"u","22"=>"v","23"=>"w","24"=>"x","25"=>"y","26"=>"z","27"=>"_");
        private $sub_par = 0;
        private $lenght = 0;
        private $plaintext = "";
        private $ciphertext = "";
        private $key_a = array();
                
        public function __construct($key, $padding_par){
                $this->key = $key;
                $this->padding_par = $padding_par;
                $this->sub_par = $this-> _sp($this->padding_par, $this->key);
                $this->lenght = strlen($this->key);
                $this->key_a = str_split($this->key);
        }
        
        public function _encrypt($plaintext){
                try{
                        $this->ciphertext = "";
                        $this->plaintext = $plaintext;
                        
                        //- split the plaintext into block of lenght = key lenght [1]
                        //- index each block using the key [2]
                        //- and sort each block by the key's index [3]
                        $plain_a = str_split($this->plaintext, $this->lenght); /*[1]*/
                        
                        foreach ($plain_a as $block) { /*[2]*/
                                $empty_space=strlen($block)% $this->lenght;
                                if( $empty_space > 0) {for($j=1; $j<=($this->lenght-$empty_space); $j++) {$block .="-";}}
                                
                                $block_a = str_split($block);
                                $tmp = array(); //- we put all the changes in a temp array first
                                for($i = 0; $i < $this->lenght; $i++){
                                        $tmp[$this->key_a[$i]] = (int)array_search($block_a[$i], $this->alphabet)+$this->padding_par; /*[4]*/
                                        unset($block_a[$i]);        
                                }
                                $block_a = $tmp; unset($tmp);
                                ksort($block_a); /*[3]*/
                                $this->ciphertext .= implode("",$block_a);
                        }
                        $this->ciphertext = $this->ciphertext - $this->sub_par;  
                        
                        return $this->ciphertext;
                        
                }
                catch(Exception $e){
                        die ("An error occured");
                }
                
        }
        
        private function alpha(&$item, $key, $parameter){
                $item = (int)$item;
                $item = $item - $parameter;
                if(strlen($item) == 1) $item ="0".$item;
                if (isset($this->alphabet[$item])) $item = $this->alphabet[$item];
                else $item = "-";                        
        }
        
        public function _decrypt($ciphertext){
                try{                
                        $this->plaintext = "";
                        $this->ciphertext = $ciphertext;
                        $this->ciphertext = $this->ciphertext + $this->sub_par;  
            
                        //- split the ciphertext into block of lenght = string lenght of the items in $alphabet = 2 [1]
                        //- for each block, unpad and map to the alphabet character [2]
                        //- form super-block of lenght = key lenght [3]
                        //- sort the key in ascending order [4]
                        //- index each super-block with the sorted key [5]
                        //- bring the plaintext back by bringing the indexes(key digits) to the original order of the key. [6]

                        $cipher_a = str_split($this->ciphertext, 2); /*[1]*/
                        
                        if($this->lenght%count($this->ciphertext)==0) {
                                                
                                array_walk( $cipher_a , array($this,'alpha'), $this->padding_par); /*[2]*/
                                $cipher_a = array_chunk( $cipher_a, $this->lenght); /*[3]*/
                                asort($this->key_a); /*[4]*/
                                
                                foreach($cipher_a as $block_a){
                                        $tmp = array(); $i= 0;
                                        foreach($this->key_a as $k=>$v){ /*[5]*/
                                                if(isset($block_a[$i])) {
                                                        $tmp[$v] = $block_a[$i];
                                                        unset($block_a[$i]);
                                                }
                                                else $tmp[$v] = "-"; //e.g: 25 31 21 --
                                                $i++;
                                        }
                                        $block_a = $tmp; unset($tmp);
                                        $block_a = $this->referential_ksort($block_a,$this->key); /*[6]*/
                                        $this->plaintext .= implode("", $block_a);
                                 }
                                 
                                 return $this->plaintext;
                                
                         }
                         else throw new Exception("Invalid ciphertext");
                }
                catch(Exception $e){
                        die ("An error occured");
                }
        }
        
        private function referential_ksort($array, $sequence){
                //sorting by array index and also by following a given sequence
                $sequence_a = str_split($sequence);$temp = array();
                foreach ($sequence_a as $s) $temp[$s] = $array[$s];
                unset($array);
                return $temp;
        }
        
        private function _sp($pad,$len){
                $sp = "";
                for($i=0; $i<$len; $i++) $sp.=(int)($pad/2); //- so that the substraction will always be > 0
                return $sp;
        }
}
