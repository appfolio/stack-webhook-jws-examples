require 'net/http'
require 'uri'
require 'base64'
require 'json'
require 'jwt'

JWKS_URI = 'https://api.appfolio.com/.well-known/jwks.json'
HEADER   = 'X-JWS-Signature'

class WebhookController < ApplicationController
  skip_before_action :verify_authenticity_token

  def receive_webhook
    signature = request.headers[HEADER]

    if signature.blank?
      render json: { error: "Missing #{HEADER} header" }, status: :bad_request
      return
    end

    encoded_header, encoded_signature = signature.split('..')
    if encoded_header.blank? || encoded_signature.blank?
      render json: { error: "Invalid signature format" }, status: :bad_request
      return
    end

    encoded_payload = Base64.urlsafe_encode64(request.raw_post).gsub(/=+$/, '')
    message = "#{encoded_header}.#{encoded_payload}.#{encoded_signature}"

    begin
      uri = URI(JWKS_URI)
      response = Net::HTTP.get(uri)
      jwks_data = JSON.parse(response)
    rescue StandardError => e
      render json: { error: "Failed to fetch JWKS: #{e.message}" }, status: :internal_server_error
      return
    end

    jwks = JWT::JWK::Set.new(jwks_data)
  
    begin
      JWT.decode(message, nil, true, algorithms: 'PS256', jwks: jwks)
    rescue JWT::DecodeError => e
      render json: { error: "Failed to verify signature: #{e.message}" }, status: :unauthorized
      return
    end

    render json: { message: 'Webhook received and signature verified' }, status: :ok
  end
end
