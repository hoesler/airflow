# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

import json
from typing import Any, Generic, TypeVar, TYPE_CHECKING

from azure.core.credentials import TokenCredential
from azure.core.credentials_async import AsyncTokenCredential
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.identity.aio import (
    ClientSecretCredential as AsyncClientSecretCredential,
    DefaultAzureCredential as AsyncDefaultAzureCredential,
)

from airflow.exceptions import AirflowException
from airflow.hooks.base import BaseHook
from airflow.models import Connection

if TYPE_CHECKING:
    from typing_extensions import Protocol
else:
    Protocol = object

T = TypeVar("T", covariant=True)


class AzureManagementClientSupplier(Protocol[T]):
    def __call__(
        self,
        credentials,  # type: "TokenCredential"
        subscription_id,  # type: str
    ) -> T:
        ...


class AzureIdentityAuthMixin:
    def _get_credential(
        self: BaseHook, conn: Connection, client_secret_creds_type, default_creds_type
    ):
        def create_credentials_from_json(credential_config: dict):
            return client_secret_creds_type(
                tenant_id=credential_config["tenantId"],
                client_id=credential_config["clientId"],
                client_secret=credential_config["clientSecret"],
                authority=credential_config.get("activeDirectoryEndpointUrl"),
            )

        key_path = conn.extra_dejson.get("key_path")
        if key_path:
            if not key_path.endswith(".json"):
                raise AirflowException("Unrecognised extension for key file.")
            self.log.info("Getting connection using a JSON key file.")
            with open("credentials.json") as json_file:
                json_dict = json.load(json_file)
                return create_credentials_from_json(json_dict)

        key_json = conn.extra_dejson.get("key_json")
        if key_json:
            self.log.info("Getting connection using a JSON config.")
            return create_credentials_from_json(key_json)

        if conn.login is not None and conn.password is not None:
            self.log.info(
                "Getting connection using specific credentials and subscription_id."
            )
            tenant_id = conn.extra_dejson.get(
                "extra__azure__tenantId"
            ) or conn.extra_dejson.get("tenantId")

            return client_secret_creds_type(
                client_id=conn.login, client_secret=conn.password, tenant_id=tenant_id
            )

        return default_creds_type()

    def get_credential(
        self: AzureIdentityAuthMixin, conn: Connection
    ) -> TokenCredential:
        return self._get_credential(
            conn, ClientSecretCredential, DefaultAzureCredential
        )

    def get_async_credential(
        self: AzureIdentityAuthMixin, conn: Connection
    ) -> AsyncTokenCredential:
        return self._get_credential(
            conn, AsyncClientSecretCredential, AsyncDefaultAzureCredential
        )


class AzureBaseHook(AzureIdentityAuthMixin, BaseHook, Generic[T]):
    """
    This hook acts as a base hook for azure services.

    It offers several authentication mechanisms to authenticate
    the client library used for upstream azure hooks.

    :param sdk_client: The SDKClient to use.
    :param conn_id: The :ref:`Azure connection id<howto/connection:azure>`
        which refers to the information to connect to the service.
    """

    conn_name_attr = "azure_conn_id"
    default_conn_name = "azure_default"
    conn_type = "azure"
    hook_name = "Azure"

    @classmethod
    def get_connection_form_widgets(cls) -> dict[str, Any]:
        """Returns connection widgets to add to connection form."""
        from flask_appbuilder.fieldwidgets import BS3TextFieldWidget
        from flask_babel import lazy_gettext
        from wtforms import StringField

        return {
            "extra__azure__tenantId": StringField(
                lazy_gettext("Azure Tenant ID"), widget=BS3TextFieldWidget()
            ),
            "extra__azure__subscriptionId": StringField(
                lazy_gettext("Azure Subscription ID"), widget=BS3TextFieldWidget()
            ),
        }

    @classmethod
    def get_ui_field_behaviour(cls) -> dict[str, Any]:
        """Returns custom field behaviour."""
        import json

        return {
            "hidden_fields": ["schema", "port", "host"],
            "relabeling": {
                "login": "Azure Client ID",
                "password": "Azure Secret",
            },
            "placeholders": {
                "extra": json.dumps(
                    {
                        "key_path": "path to json file for auth",
                        "key_json": "specifies json dict for auth",
                    },
                    indent=1,
                ),
                "login": "client_id (token credentials auth)",
                "password": "secret (token credentials auth)",
                "extra__azure__tenantId": "tenantId (token credentials auth)",
                "extra__azure__subscriptionId": "subscriptionId",
            },
        }

    def __init__(
        self,
        sdk_client: AzureManagementClientSupplier[T],
        conn_id: str = "azure_default",
    ):
        self.sdk_client = sdk_client
        self.conn_id = conn_id
        super().__init__()

    def get_conn(self) -> T:
        """
        Authenticates the resource using the connection id passed during init.

        :return: the authenticated client.
        """
        conn = self.get_connection(self.conn_id)

        subscription_id = conn.extra_dejson.get(
            "extra__azure__subscriptionId"
        ) or conn.extra_dejson.get("subscriptionId")

        if subscription_id is None:
            raise AirflowException(
                "subscriptionId not found in connection " + self.conn_id
            )

        return self.sdk_client(
            credentials=self.get_credential(conn),
            subscription_id=subscription_id,
        )
