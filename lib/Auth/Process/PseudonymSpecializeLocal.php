<?php
/**
 * Filter to specialize polymorphic pseudonyms locally
 * 
 * @author Hans Harmannij
 */
class sspmod_polypseud_Auth_Process_PseudonymSpecializeLocal extends SimpleSAML_Auth_ProcessingFilter {

    private $in_attribute = 'nameid';
    private $out_attribute = 'pseudonym';
    private $dp;
    private $dk;

    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);
        assert('is_array($config)');
        if (array_key_exists('inAttribute', $config)) {
            $this->in_attribute = $config['inAttribute'];
        }
        if (array_key_exists('outAttribute', $config)) {
            $this->out_attribute = $config['outAttribute'];
        }
        if (array_key_exists('Dp', $config)) {
            $this->dp = $config['Dp'];
        }
        else {
            throw new SimpleSAML_Error_Exception('PseudonymSpecializeLocal config does not contain a Dp');
        }
        if (array_key_exists('Dk', $config)) {
            $this->dk = $config['Dk'];
        }
        else {
            throw new SimpleSAML_Error_Exception('PseudonymSpecializeLocal config does not contain a Dk');
        }
    }

    public function process(&$request) {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $attributes =& $request['Attributes'];

        if(array_key_exists($this->in_attribute, $attributes)) {
            $sp = NULL;
            if(array_key_exists('saml:RequesterID', $request) && !empty($request['saml:RequesterID'])) {
                $sp = $request['saml:RequesterID'];
            }
            else if(array_key_exists('core:SP', $request) && !empty($request['core:SP'])) {
                $sp = $request['core:SP'];
            }
            else {
                throw new SimpleSAML_Error_Exception('No SP id found for specializing pseudonym'); 
            }

	        SimpleSAML_Logger::debug("PolyPseud specializing pseudonym from attribute $this->in_attribute");
            $attributes[$this->out_attribute] = array(polypseud_specialize($attributes[$this->in_attribute][0], $sp, $this->dp, $this->dk));
        }
        else {
            throw new SimpleSAML_Error_Exception('Could not specialize the polymorphic pseudonym. inAttribute is missing');
        }


    }
}
