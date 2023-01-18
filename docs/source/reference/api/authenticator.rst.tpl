{{ module }}
{{ module | length * '=' }}

.. automodule:: {{ module }}

{% for cls in classes %}
.. autoclass:: {{ cls }}
{% endfor -%}

{%- for cls in configurables %}
.. autoconfigurable:: {{ cls }}
{% endfor %}
