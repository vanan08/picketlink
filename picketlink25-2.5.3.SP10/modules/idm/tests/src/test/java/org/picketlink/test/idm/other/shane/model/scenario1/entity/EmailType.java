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
package org.picketlink.test.idm.other.shane.model.scenario1.entity;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * Lookup table containing email address types, e.g. "work", "personal", etc.
 *
 * @author Shane Bryzak
 */
@Entity
public class EmailType implements Serializable {
    private static final long serialVersionUID = 4197032448970533333L;

    @Id @GeneratedValue private Long emailTypeId;
    private String description;

    public Long getEmailTypeId() {
        return emailTypeId;
    }

    public void setEmailTypeId(Long emailTypeId) {
        this.emailTypeId = emailTypeId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
