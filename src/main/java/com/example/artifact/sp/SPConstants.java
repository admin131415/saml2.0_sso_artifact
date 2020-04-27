package com.example.artifact.sp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Privat on 4/7/14.
 */
public class SPConstants {
    public static final String SP_ENTITY_ID = "TestSP";
    public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
    //
    public static final String GOTO_URL_SESSION_ATTRIBUTE = "http://localhost:8081/index.html";
    public static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8081/sp/consumer";
    /**
     * sp 端cookie的key
     */
    public static final String SP_COOKIE_KEY = "sp_cookie_key";
    /**
     * sp 端cookie的value
     */
    public static final String SP_COOKIE_VALUE = "sp_cookie_value";
}
