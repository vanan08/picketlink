/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.idm.jpa.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * <p>Specifies that a property should be mapped to a specific field of a {@link org.picketlink.idm.credential.storage.CredentialStorage}.</p>
 *
 * @author Shane Bryzak
 * @author Pedro Igor
 */
@Target({METHOD, FIELD})
@Documented
@Retention(RUNTIME)
@Inherited
public @interface CredentialProperty {

    /**
     * <p>(Optional) The field from the corresponding {@link org.picketlink.idm.credential.storage.CredentialStorage} class
     * that is mapped to this property.</p>
     * <p>If no <code>name</code> is provided, the property name will be used to match the corresponding field on the storage class.</p>
     *
     *
     * @return
     */
    String name() default "";

}
