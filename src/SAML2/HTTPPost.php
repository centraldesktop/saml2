<?php

/**
 * Class which implements the HTTP-POST binding.
 *
 * @package simpleSAMLphp
 * @version $Id$
 */
class SAML2_HTTPPost extends SAML2_Binding
{
    /**
     * Send a SAML 2 message using the HTTP-POST binding.
     *
     * Note: This function never returns.
     *
     * @param SAML2_Message $message The message we should send.
     */
    public function send(SAML2_Message $message)
    {
        if ($this->destination === NULL) {
            $destination = $message->getDestination();
        } else {
            $destination = $this->destination;
        }
        $relayState = $message->getRelayState();

        $msgStr = $message->toSignedXML();
        $msgStr = $msgStr->ownerDocument->saveXML($msgStr);

        SAML2_Utils::getContainer()->debugMessage($msgStr, 'out');

        $msgStr = base64_encode($msgStr);

        if ($message instanceof SAML2_Request) {
            $msgType = 'SAMLRequest';
        } else {
            $msgType = 'SAMLResponse';
        }

        $post = array();
        $post[$msgType] = $msgStr;

        if ($relayState !== NULL) {
            $post['RelayState'] = $relayState;
        }

        SAML2_Utils::getContainer()->postRedirect($destination, $post);
    }

    /**
     * Receive a SAML 2 message sent using the HTTP-POST binding.
     *
     * Throws an exception if it is unable receive the message.
     *
     * @return SAML2_Message The received message.
     * @throws Exception
     */
    public function receive()
    {
        if (array_key_exists('SAMLRequest', $_POST)) {
            $msg = $_POST['SAMLRequest'];
        } elseif (array_key_exists('SAMLResponse', $_POST)) {
            $msg = $_POST['SAMLResponse'];
        } else {
            throw new Exception('Missing SAMLRequest or SAMLResponse parameter.');
        }

        $msg = base64_decode($msg);


        SAML2_Utils::getContainer()->debugMessage($msg, 'in');

	
        // PHP c14n doesn't normalize to the same spec as ADFS,
        // in fact it eats \r so this can't be done AFTER this is parsed into the DOM document space
        // Ff there is a \r\n in one of the the claim rules / attribute statements
        // validation will fail.  The spec makes mention of the \n => $xA rule a lot
        // but there isn't much mention of the \r -> #xD rule which is apparently
        // something ADFS does.  Do this too.
        // This is a mega hack, this library is no longer being manintained,
        // look at checking this behavior in the "new" upstream for simplesaml/saml2
        // which is apparently ass/XmlSecurity
        $msg = preg_replace("/\r\n/","&#xD;&#xA;", $msg);

        $document = new DOMDocument();
        $document->loadXML($msg);
        $xml = $document->firstChild;

        $msg = SAML2_Message::fromXML($xml);

        if (array_key_exists('RelayState', $_POST)) {
            $msg->setRelayState($_POST['RelayState']);
        }

        return $msg;
    }

}
