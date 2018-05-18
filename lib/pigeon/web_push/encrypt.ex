defmodule Pigeon.WebPush.Encrypt do
  @moduledoc false

  defstruct mode: nil,
            auth_token: nil,
            cek: nil,
            cek_info: nil,
            context: nil,
            ciphertext: nil,
            local_private_key: nil,
            local_public_key: nil,
            nonce: nil,
            nonce_info: nil,
            psuedo_random: nil,
            public_key: nil,
            salt: nil,
            shared_secret: nil,
            cleartext: nil

  @type supported_ciphers :: :aes_gcm

  @type t :: %__MODULE__{
          mode: supported_ciphers,
          auth_token: binary,
          cek: binary,
          cek_info: binary,
          context: binary,
          ciphertext: binary,
          local_private_key: binary,
          local_public_key: binary,
          nonce: binary,
          nonce_info: binary,
          psuedo_random: binary,
          public_key: binary,
          salt: binary,
          shared_secret: binary,
          cleartext: String.t()
        }

  @type encrypted :: %{
          ciphertext: binary,
          salt: String.t(),
          public_key: String.t()
        }

  @doc """
  Encrypts a term for transmission as a JSON string via Web Push.

  ## Options

  The accepted arguments are:

    * `payload` - term to be encrypted
    * `p256dh` - an Elliptic curve Diffie–Hellman public key on the P-256 curve, usually taken from the browser's web push subscription 
    * `auth` - An authentication secret, usually taken from the browser's web push subscription 
    * `min_size` - optional, pad `payload` to this byte size if required (default: 0)
    * `mode` - optional encryption mode, only :aes_gcm supported currently 

  """
  @spec encrypt(
          term(),
          String.t(),
          String.t(),
          non_neg_integer,
          supported_ciphers
        ) :: encrypted
  def(encrypt(payload, p256dh, auth, min_size \\ 0, mode)) do
    %__MODULE__{mode: mode}
    |> set_unencrypted(payload, min_size)
    |> set_public_key(p256dh)
    |> set_auth_token(auth)
    |> set_salt()
    |> set_local_keys()
    |> set_shared_secret()
    |> set_psuedo_random()
    |> set_context()
    |> set_cek_info()
    |> set_cek()
    |> set_nonce_info()
    |> set_nonce()
    |> perform_encryption()
    |> encode()
  end

  defp encode(s) do
    output = %{}

    Map.put(output, :ciphertext, s.ciphertext)
    |> Map.put(:salt, Base.url_encode64(s.salt, padding: false))
    |> Map.put(
      :public_key,
      Base.url_encode64(s.local_public_key, padding: false)
    )
  end

  defp perform_encryption(s) do
    {ciphertext, ciphertag} =
      :crypto.block_encrypt(s.mode, s.cek, s.nonce, {"", s.cleartext})

    %{s | :ciphertext => ciphertext <> ciphertag}
  end

  defp set_nonce(s) do
    nonce = derive(s.salt, s.psuedo_random, s.nonce_info, 12)
    %{s | :nonce => nonce}
  end

  defp set_nonce_info(%__MODULE__{mode: :aes_128_gcm} = s) do
    nonce_info = info_encoding("nonce")
    %{s | :nonce_info => nonce_info}
  end

  defp set_nonce_info(s) do
    nonce_info = info_encoding("nonce", s.context)
    %{s | :nonce_info => nonce_info}
  end

  defp set_cek(s) do
    cek = derive(s.salt, s.psuedo_random, s.cek_info, 16)
    %{s | :cek => cek}
  end

  defp set_cek_info(%__MODULE__{mode: :aes_128_gcm} = s) do
    cek_info = info_encoding("aes128gcm")

    %{s | :cek_info => cek_info}
  end

  defp set_cek_info(s) do
    cek_info = info_encoding("aesgcm", s.context)

    %{s | :cek_info => cek_info}
  end

  defp set_context(%__MODULE__{mode: :aes_128_gcm} = s), do: s

  defp set_context(s) do
    context =
      <<byte_size(s.public_key)::integer-size(16)>> <>
        s.public_key <>
        <<byte_size(s.local_public_key)::integer-size(16)>> <>
        s.local_public_key

    %{s | :context => context}
  end

  defp set_psuedo_random(s) do
    encoding = prk_encoding(s)

    hmac = derive(s.auth_token, s.shared_secret, encoding, 32)

    %{s | :psuedo_random => hmac}
  end

  defp prk_encoding(%__MODULE__{mode: :aes_128_gcm} = s) do
    "WebPush: info" <> <<0>> <> s.public_key <> s.local_public_key
  end

  defp prk_encoding(_s) do
    "Content-Encoding: auth" <> <<0>>
  end

  defp set_shared_secret(s) do
    secret =
      :crypto.compute_key(:ecdh, s.public_key, s.local_private_key, :prime256v1)

    %{s | :shared_secret => secret}
  end

  defp set_local_keys(s) do
    {public, private} = :crypto.generate_key(:ecdh, :prime256v1)

    Map.put(s, :local_public_key, public)
    |> Map.put(:local_private_key, private)
  end

  defp set_salt(s) do
    salt = :crypto.strong_rand_bytes(16)
    %{s | :salt => salt}
  end

  defp set_public_key(s, p256dh) do
    public = Base.url_decode64!(p256dh, padding: false)
    %{s | :public_key => public}
  end

  defp set_auth_token(s, auth) do
    token = Base.url_decode64!(auth, padding: false)
    %{s | :auth_token => token}
  end

  defp set_unencrypted(s, data, min_size) do
    cleartext =
      jsonify(data)
      |> pad_data(min_size, s.mode)

    %{s | :cleartext => cleartext}
  end

  defp info_encoding(type, context) do
    "Content-Encoding: " <> type <> <<0>> <> "P-256" <> <<0>> <> context
  end

  defp info_encoding(type) do
    "Content-Encoding: " <> type <> <<0>>
  end

  defp derive(salt, input, extra, size) do
    hmac =
      :crypto.hmac_init(:sha256, salt)
      |> :crypto.hmac_update(input)
      |> :crypto.hmac_final()

    :crypto.hmac_init(:sha256, hmac)
    |> :crypto.hmac_update(extra)
    |> :crypto.hmac_update(<<1>>)
    |> :crypto.hmac_final()
    |> :binary.part(0, size)
  end

  defp jsonify(data) when is_binary(data), do: data

  defp jsonify(data) do
    Poison.encode!(data)
  end

  defp pad_data(data, min, :aes_128_gcm) when byte_size(data) >= min do
    data <> <<2>>
  end

  defp pad_data(data, min, _mode) when byte_size(data) >= min do
    <<0::integer-size(16)>> <> data
  end

  defp pad_data(data, min, mode) do
    count = min - byte_size(data)

    add_padding(data, count, mode)
  end

  defp add_padding(data, count, :aes_128_gcm) do
    data <> <<2>> <> :binary.copy(<<0>>, count)
  end

  defp add_padding(data, count, _mode) do
    <<count::integer-size(16)>> <> :binary.copy(<<0>>, count) <> data
  end
end
