import pytest

from aegis.data.talkingdata import FEATS, benchmark, featurize, load, make_synthetic_sample


def test_adapter_schema_features_and_benchmark(tmp_path):
    p = make_synthetic_sample(tmp_path / "td.csv", 12000)
    df = load(p)
    f = featurize(df)
    assert list(f.columns) == FEATS and len(f) == len(df) and not f.isna().any().any()
    assert (f["ip_clicks_prior"] >= 0).all()  # causal: counts only past clicks
    r = benchmark(p)
    assert set(r["models"]) == {"hgb", "mlp"} and 0 <= r["models"]["hgb"]["roc_auc"] <= 1


def test_adapter_rejects_wrong_schema(tmp_path):
    (tmp_path / "bad.csv").write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        load(tmp_path / "bad.csv")
