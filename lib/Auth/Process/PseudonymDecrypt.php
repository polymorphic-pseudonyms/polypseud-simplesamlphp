<?php
/**
 * Filter to decrypt Encrypted Pseudonyms
 * 
 * @author Hans Harmannij
 */
class sspmod_polypseud_Auth_Process_PseudonymDecrypt extends SimpleSAML_Auth_ProcessingFilter {

    private $in_attribute = 'nameid';
    private $out_attribute = 'pseudonym';
    private $failSilently = false;
    private $privatekey;
    private $closingkey;

    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);
        assert('is_array($config)');
        if (array_key_exists('encryptedAttribute', $config)) {
            $this->in_attribute = $config['encryptedAttribute'];
        }
        if (array_key_exists('pseudonymAttribute', $config)) {
            $this->out_attribute = $config['pseudonymAttribute'];
        }
        if (array_key_exists('privateKey', $config)) {
            $this->privkey = $config['privateKey'];
        }
        else {
            throw new SimpleSAML_Error_Exception('PseudonymDecrypt config does not contain a private key');
        }
        if (array_key_exists('closingKey', $config)) {
            $this->closingkey = $config['closingKey'];
        }
        else {
            throw new SimpleSAML_Error_Exception('PseudonymDecrypt config does not contain a closing key');
        }
        if (array_key_exists('failSilently', $config)) {
            $this->failSilently = $config['failSilently'];
        }
    }

    public function process(&$request) {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $attributes =& $request['Attributes'];

        if(array_key_exists($this->in_attribute, $attributes)) {
	        SimpleSAML_Logger::debug("PolyPseud decrypting pseudonym from attribute $this->in_attribute");
            try {
                $attributes[$this->out_attribute] = array(polypseud_decrypt($attributes[$this->in_attribute][0], $this->privkey, $this->closingkey));
            }
            catch (DecryptException $e) {
                if($this->failSilently === false) {
                    throw new SimpleSAML_Error_Exception("Could not decrypt pseudonym.", 0, $e);
                }
            }
            catch (Exception $e) {
                throw new SimpleSAML_Error_Exception("Could not decrypt pseudonym.", 0, $e);
            }
        }
    }
}

class DecryptException extends Exception
{
    public function __construct($message, $code = 0, Exception $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}
