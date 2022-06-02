$schema: http://json-schema.org/draft-07/schema#
title: username_derivation
type: object
additionalProperties: false
required:
  - username_derivation
properties:
  username_derivation:
    type: object
    additionalProperties: false
    properties:
      username_claim:
        type: string
      action:
        type: string
        enum:
          - strip_idp_domain
          - prefix
      domain:
        type: string
      prefix:
        type: string
    required:
      - username_claim
      - action
    allOf:
      - if:
          properties:
            action:
              const: strip_idp_domain
        then:
          required:
            - domain
      - if:
          properties:
            action:
              const: prefix
        then:
          required:
            - prefix
