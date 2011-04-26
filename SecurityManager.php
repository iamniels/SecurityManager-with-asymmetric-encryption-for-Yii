<?php
/**
 * This class extends the basic functionality of Yii's CSecurityManager with
 * methods to implement asymmetric encryption in small applications. To use this
 * component you need the OpenSSL PHP extension.
 * 
 * @author  i.amniels.com
 * @version 0.1
 * 
 * @license Everyone is permitted to copy and distribute verbatim or modified
 * copies of this document as long as there is a hyperlink to
 * http://i.amniels.com/mysql-database-encryption-using-public-private-keys
 * without the nofollow attribute published with the copy. This document comes
 * without warranty.
 *
 * How to use this component:
 * 1. Copy this file to the components directory. Enable it in the application
 *    configuration file under components:
 * <code>
 *  'securityManager'=>array(
 *           'class'=>'SecurityManager',
 *           'asymPublicKeyFile'=>'application.data.publickey',
 *  ),
 * </code>
 * 2. Generate a key pair using generateAsymNewKeyPair() once (!!).
 * 3. Encrypt some data with the public key using asymEncrypt($data).
 * 4. Store a private key in the user's session using storeAsymPrivateKey($key).
 * 5. Decrypt the encrypted data using asymDecrypt($data).
 */
class SecurityManager extends CSecurityManager{

    /**
     * Location of the public key file. Set it's value in the app's
     * configuration.
     * @access public
     * @var string
     */
    public $asymPublicKeyFile;

    /**
     * Key used to store the private key in session storage. Change in app's
     * config when 'encrypted_private_key' is already in use.
     * @access public
     * @var string
     */
    public $epkSessionName = 'encrypted_private_key';

    /**
     * Public key
     * @access private
     * @var string
     */
    private $asymPublicKey;

    /**
     * Private key
     * @access private
     * @var string
     */
    private $asymPrivateKey;

    /**
     * Stores $key in session storage. Uses the Yii CHttpSession component.
     * @param string $key
     */
    public function storeAsymPrivateKey($key){
        Yii::app()->session->add($this->epkSessionName, $key);
    }

    /**
     * Checks whether both private and public keys are available.
     * @return boolean
     */
    public function hasAsymKeys(){
        try{
            $this->getAsymPrivateKey();
            $this->getAsymPublicKey();
        }catch(Exception $e){
            return false;
        }
        return true;
    }

    /**
     * Decrypts data with the private key from session storage.
     * @param binary $encrypted
     * @return string
     */
    public function asymDecrypt($encrypted){
        $key = $this->getAsymPrivateKey();
        openssl_private_decrypt($encrypted, $decrypted, $key);
        return $decrypted;
    }

    /**
     * Encrypts data with the public key. Gets key from file.
     * @param string $data
     * @return binary
     */
    public function asymEncrypt($data){
        $key = $this->getAsymPublicKey();
        openssl_public_encrypt($data, $encrypted, $key);
        return $encrypted;
    }

    /**
     * Get the private key if it is stored before with storeAsymPrivateKey()
     * @return string
     */
    public function getAsymPrivateKey(){
        if(!isset($this->asymPrivateKey)){
            $this->asymPrivateKey = Yii::app()->session->get($this->epkSessionName, false);
        }
        if(!$this->asymPrivateKey){
            throw new Exception("No private key is stored in session at {$this->epkSessionName}.");
        }
        return $this->asymPrivateKey;
    }

    /**
     * Generates a key pair to use for asymmetric encryption. After generation
     * the private key is available with getPrivateKey() and the public key is
     * stored in the public key file. An excisting key pair will be overwritten!
     * Do not use this method when data is encrypted with current key pair,
     * otherwise data will get lost.
     */
    public function generateAsymNewKeyPair(){
        $res = openssl_pkey_new();
        /* Extract the private key from $res */
        openssl_pkey_export($res, $this->asymPrivateKey);
        /* Extract the public key from $res */
        $pubKey = openssl_pkey_get_details($res);
        $this->asymPublicKey = $pubKey["key"];
        /* Write public key to file */
        $this->putKeyInFile($this->asymPublicKey, $this->asymPublicKeyFile);
        Yii::app()->session->add($this->epkSessionName, $this->asymPrivateKey);
    }

    /**
     * Returns the public key stored in the key file.
     * @return string
     */
    protected function getAsymPublicKey(){
        if(!isset($this->asymPublicKey)){
            $this->asymPublicKey = $this->getKeyFromFile($this->asymPublicKeyFile);
        }
        return $this->asymPublicKey;
    }

    /**
     * Returns the full path of $fileAlias. $fileAlias can be a file path with
     * / as directory separator, or it can be a file alias. Extensions are not
     * allowed when $fileAlias is an alias.
     * @access protected
     * @param string $fileAlias
     * @return string
     */
    protected function getFileName($fileAlias){
        if(strpos($fileAlias, '/') !== false){
            $file = $fileAlias;
        }else{
            $file = Yii::getPathOfAlias($fileAlias);
        }
        if(!is_file($file)){
            throw new CException("Could not find file {$file}");
        }
        return $file;
    }

    /**
     * Get the public key from a local file.
     * @access protected
     * @param string $fileAlias
     * @return string
     */
    protected function getKeyFromFile($fileAlias){
        $file = $this->getFileName($fileAlias);
        $key = file_get_contents($file);
        if($key === false){
            throw new CException("Could not read file {$file}");
        }
        if(!$key){
            Yii::log("Key file {$file} is empty.", 'warning', 'app.securitymanager');
        }
        return $key;
    }

    /**
     * Write the public key to a local file.
     * @access protected
     * @param string $key
     * @param string $fileAlias
     */
    protected function putKeyInFile($key, $fileAlias){
        $file = $this->getFileName($fileAlias);
        if(file_put_contents($file, $key) === false){
            throw new CException("Could not write key to file {$file}.");
        }
    }
}
?>

