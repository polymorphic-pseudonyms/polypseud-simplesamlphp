<?php
/**
 * Filter to generate Polymorphic Pseudonyms
 * 
 * @author Hans Harmannij
 */
class sspmod_polypseud_Auth_Process_PseudonymEncrypt extends SimpleSAML_Auth_ProcessingFilter {

    private $in_attribute = 'nameid';
    private $out_attribute = 'pseudonym';
    private $y_k;

    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);
        assert('is_array($config)');
        if (array_key_exists('inAttribute', $config)) {
            $this->in_attribute = $config['inAttribute'];
        }
        if (array_key_exists('outAttribute', $config)) {
            $this->out_attribute = $config['outAttribute'];
        }
        if (array_key_exists('yK', $config)) {
            $this->y_k = $config['yK'];
        }
        else {
            throw new SimpleSAML_Error_Exception('PseudonymEncrypt config does not contain a system key yK');
        }
    }

    public function process(&$request) {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $attributes =& $request['Attributes'];

        if(array_key_exists($this->in_attribute, $attributes)) {
	        SimpleSAML_Logger::debug("PolyPseud generating pseudonym from attribute $this->in_attribute");
            $attributes[$this->out_attribute] = array(polypseud_generate_pp($this->y_k, $attributes[$this->in_attribute][0]));
        }
        else {
            throw new SimpleSAML_Error_Exception('Could not generate a polymorphic pseudonym. inAttribute is missing');
        }


    }
}

class EncryptException extends Exception
{
    public function __construct($message, $code = 0, Exception $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}
