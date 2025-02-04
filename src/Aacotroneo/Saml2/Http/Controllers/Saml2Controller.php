<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use Cookie;

//NEEDED TO JIMMY-RIG LOGIN FROM WALTS COOKIE

class Saml2Controller extends Controller
{

    protected $saml2Auth;

    /**
     * @param Saml2Auth $saml2Auth injected.
     */
    function __construct(Saml2Auth $saml2Auth)
    {
        $this->saml2Auth = $saml2Auth;
    }


    /**
     * Generate local sp metadata
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {

        $metadata = $this->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is Found
     */
    public function acs()
    {
        $errors = $this->saml2Auth->acs();
        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $this->saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$this->saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }
        $user = $this->saml2Auth->getSaml2User();
        $attributes_needed = $user->getAttributes();
        //session(['SAML_NAMEID' => $attributes_needed['email'][0]]);

        event(new Saml2LoginEvent($user, $this->saml2Auth));
        $redirectUrl = $user->getIntendedUrl();
        logger()->error('Set Redirect URL: ' . $redirectUrl);
        logger()->error('Relay URL in REQUEST: ' . app('request')->input('RelayState'));
        logger()->error('Relay URL in GET: ' . app('request')->query('RelayState'));
        logger()->error('Relay URL in GET: ' . app('request')->query('RelayState'));
        if (!is_array($attributes_needed) || empty($attributes_needed)) {
            logger()->error('SAML: No attributes needed');
        } else {
            if (empty($attributes_needed['email'])) {
                logger()->error('SAML: No email attribute');
            } else {
                logger()->error('SAML: email: ' . $attributes_needed['email'][0]);
            }
        }
        $testUser = auth()->user();
        if (is_object($testUser)) {
            if (property_exists($testUser, 'okta_account_id')) {
                logger()->error('User name: ' . auth()->user()->okta_account_id);
            }
        }

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } else {

            return redirect(config('saml2_settings.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'saml2.logoutRequestReceived' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     */
    public function sls()
    {
        $error = $this->saml2Auth->sls(config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($error)) {
            //dd($error);
            throw new \Exception(print_r($error, true));
        }
        //remove session variable
        session()->flush();
        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     */
    public function logout(Request $request)
    {
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
        //original next line, but w Okta its different (line after)
        //$nameId = $request->query('nameId');
        $nameId = session('okta_user_data')['nameid'] ?? '';
        $this->saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
    }

    /**
     * This initiates a login request
     * origin login()
     */
    public function login()
    {
        // try to get the return URL from the get param so that it will work for Optimizely
        $url_value = request()->get(config('saml2_settings.returnUrlGetParam', 'returnUrl'));

        // if not there - try to get it from a cookie
        if (empty($url_value)) {
            $url_value = Cookie::get('login_source');
        }

        // validate the URL
        if (filter_var($url_value, FILTER_VALIDATE_URL) === false) {
            $url_value = null;
        }

        if ($url_value) {
            $url_parts = parse_url($url_value);
            if (!empty($url_parts['host']) && !in_array($url_parts['host'], $this->getAllowedHosts())) {
                $url_value = null;
            }
        }

        // If not $url_value is found (or is reset to empty)
        // use the default setting for login route (should be the suse.com home page)
        if (empty($url_value)) {
            $url_value = config('saml2_settings.loginRoute');
        }

        $this->saml2Auth->login($url_value);
    }

    protected function getAllowedHosts()
    {
        return config('saml2_settings.allowedRedirectDomains', [config('app.url', 'www.suse.com')]);
    }
}
