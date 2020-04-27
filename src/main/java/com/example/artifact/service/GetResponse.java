package com.example.artifact.service;

import net.shibboleth.utilities.java.support.collection.LockableClassToInstanceMultiMap;
import org.joda.time.DateTime;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.NamespaceManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.util.IDIndex;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.xmlsec.signature.Signature;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import java.util.List;
import java.util.Set;

@Service
public class GetResponse {


}
