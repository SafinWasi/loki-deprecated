def test_openid(test_loki, mocked_responses, openid_response):
    assert test_loki.openid_configuration == openid_response