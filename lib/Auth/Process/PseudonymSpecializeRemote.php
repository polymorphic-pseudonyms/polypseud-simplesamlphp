<?php
/**
 * Filter to specialize polymorphic pseudonyms using a remote pseudonym facility
 * 
 * @author Hans Harmannij
 */
class sspmod_polypseud_Auth_Process_PseudonymSpecializeRemote extends SimpleSAML_Auth_ProcessingFilter {

    private $in_attribute = 'nameid';
    private $out_attribute = 'pseudonym';
    private $pf_url;

    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);
        assert('is_array($config)');
        if (array_key_exists('inAttribute', $config)) {
            $this->in_attribute = $config['inAttribute'];
        }
        if (array_key_exists('outAttribute', $config)) {
            $this->out_attribute = $config['outAttribute'];
        }
        if (array_key_exists('pfURL', $config)) {
            $this->pf_url = $config['pfURL'];
        }
        else {
            throw new SimpleSAML_Error_Exception('PseudonymSpecializeRemote config does not contain a pfURL');
        }
    }

    private function specialize($pp, $sp) {
        $ch = curl_init();

        $url = str_replace('%PP%', urlencode($pp), $this->pf_url);
        $url = str_replace('%SP%', urlencode($sp), $url);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_FAILONERROR, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $ep = curl_exec($ch);

        $curlError = false;
        if($ep === false) {
            $curlError = curl_error($ch);
        }

        curl_close($ch);

        if($curlError) {
            throw new SimpleSAML_Error_Exception("Error specializing polymorphic pseudonym '$pp'.\n$curlError");
        }

        return $ep;
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
            $attributes[$this->out_attribute] = array($this->specialize($attributes[$this->in_attribute][0], $sp));
        }
        else {
            throw new SimpleSAML_Error_Exception('Could not specialize the polymorphic pseudonym. inAttribute is missing');
        }


    }
}
