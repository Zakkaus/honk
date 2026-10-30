Internal

- Two DNS tests no longer fail under load: the retry score test cannot favour the incumbent when the host stalls, and the receive-task pressure test keeps its unused port bound.
