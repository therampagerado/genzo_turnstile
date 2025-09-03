<?php
/**
 * Override AdminLoginController to add Cloudflare Turnstile validation
 */

class AdminLoginController extends AdminLoginControllerCore
{
    /**
     * Add Turnstile assets on the admin login page
     */
    public function setMedia()
    {
        parent::setMedia();

        if ($this->shouldCheckTurnstile()) {
            Media::addJsDef([
                'turnstileSiteKey' => Configuration::get('GENZO_TURNSTILE_SITE_KEY'),
                'submitsToCheck'   => [
                    'submitLogin'  => true,
                    'submitForgot' => true,
                ],
                'turnstileActive' => true,
            ]);

            $module = Module::getInstanceByName('genzo_turnstile');
            if ($module instanceof Module) {
                $this->addJS($module->getPathUri() . 'views/js/genzo_turnstile.js');
            }
        }
    }

    /**
     * Validate the Turnstile response during login submissions
     */
    public function processLogin()
    {
        if ($this->shouldCheckTurnstile()) {
            $resp = $this->validateFormSubmitToken();
            if ($resp === false || empty($resp['success'])) {
                $code = isset($resp['error-codes'][0]) ? $resp['error-codes'][0] : '';
                if ($code === 'invalid-input-secret' || $code === 'missing-input-secret') {
                    $this->errors[] = Tools::displayError(
                        Translate::getModuleTranslation(
                            'genzo_turnstile',
                            'The Turnstile secret key is invalid. Please contact the site administrator.',
                            'configure'
                        )
                    );
                } elseif ($code === 'cloudflare-no-contact') {
                    $this->errors[] = Tools::displayError(
                        Translate::getModuleTranslation(
                            'genzo_turnstile',
                            'Unable to connect to Cloudflare in order to verify the captcha. Please check your server settings or contact your hosting provider.',
                            'configure'
                        )
                    );
                } else {
                    $this->errors[] = Tools::displayError(
                        Translate::getModuleTranslation(
                            'genzo_turnstile',
                            'Your captcha was wrong. Please try again.',
                            'configure'
                        )
                    );
                }
            }
        }

        return parent::processLogin();
    }

    /**
     * Validate the Turnstile response during password recovery submissions
     */
    public function processForgot()
    {
        if ($this->shouldCheckTurnstile()) {
            $resp = $this->validateFormSubmitToken();
            if ($resp === false || empty($resp['success'])) {
                $code = isset($resp['error-codes'][0]) ? $resp['error-codes'][0] : '';
                if ($code === 'invalid-input-secret' || $code === 'missing-input-secret') {
                    $this->errors[] = Tools::displayError(
                        Translate::getModuleTranslation(
                            'genzo_turnstile',
                            'The Turnstile secret key is invalid. Please contact the site administrator.',
                            'configure'
                        )
                    );
                } elseif ($code === 'cloudflare-no-contact') {
                    $this->errors[] = Tools::displayError(
                        Translate::getModuleTranslation(
                            'genzo_turnstile',
                            'Unable to connect to Cloudflare in order to verify the captcha. Please check your server settings or contact your hosting provider.',
                            'configure'
                        )
                    );
                } else {
                    $this->errors[] = Tools::displayError(
                        Translate::getModuleTranslation(
                            'genzo_turnstile',
                            'Your captcha was wrong. Please try again.',
                            'configure'
                        )
                    );
                }
            }
        }

        return parent::processForgot();
    }

    private function shouldCheckTurnstile()
    {
        return Module::isEnabled('genzo_turnstile')
            && @filemtime(_PS_MODULE_DIR_.'genzo_turnstile/genzo_turnstile.php')
            && Configuration::get('GENZO_TURNSTILE_SITE_KEY')
            && Configuration::get('GENZO_TURNSTILE_SECRET_KEY');
    }

    private function validateFormSubmitToken()
    {
        $data = [
            'secret'   => Configuration::get('GENZO_TURNSTILE_SECRET_KEY'),
            'response' => Tools::getValue('cf-turnstile-response'),
            'remoteip' => Tools::getRemoteAddr(),
        ];

        $payload = http_build_query($data);
        $url     = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            $response = curl_exec($ch);
            curl_close($ch);
        } else {
            $options = [
                'http' => [
                    'method'  => 'POST',
                    'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                    'content' => $payload,
                    'timeout' => 3,
                ],
            ];
            $context  = stream_context_create($options);
            $response = Tools::file_get_contents($url, false, $context);
        }

        if ($response === false) {
            return ['success' => false, 'error-codes' => ['cloudflare-no-contact']];
        }

        $result = json_decode($response, true);

        if (!is_array($result)) {
            return ['success' => false, 'error-codes' => ['cloudflare-invalid-response']];
        }

        return $result;
    }
}
