def calculate_confidence(incident):
    """
    Calculate HomeSOC confidence in a correlated incident.

    This is NOT a probability that an attack is real.

    It is a heuristic confidence score based on:
    - source diversity
    - unique security signals
    - attack-stage diversity
    - cross-tool corroboration
    - duplicate-alert noise
    """

    events = incident.get(
        "events",
        []
    )

    unique_sources = {
        event["source"]
        for event in events
    }

    source_count = len(
        unique_sources
    )

    signal_count = incident.get(
        "signal_count",
        len(events)
    )

    stage_count = len(
        incident.get(
            "stages",
            []
        )
    )

    corroboration_bonus = incident.get(
        "corroboration_bonus",
        0
    )

    duplicates = incident.get(
        "suppressed_duplicates",
        0
    )


    # --------------------------------
    # Base confidence
    # --------------------------------

    score = 10


    # --------------------------------
    # Independent telemetry sources
    # Maximum contribution: 45
    # --------------------------------

    score += min(
        source_count * 15,
        45
    )


    # --------------------------------
    # Unique security signals
    # Maximum contribution: 20
    # --------------------------------

    score += min(
        signal_count * 4,
        20
    )


    # --------------------------------
    # Attack-stage diversity
    # Maximum contribution: 12
    # --------------------------------

    score += min(
        stage_count * 3,
        12
    )


    # --------------------------------
    # Cross-tool corroboration
    # Maximum contribution: 15
    # --------------------------------

    score += min(
        corroboration_bonus,
        15
    )


    # --------------------------------
    # Duplicate noise penalty
    # Maximum penalty: 15
    # --------------------------------

    score -= min(
        duplicates * 5,
        15
    )


    # Clamp confidence between 0 and 100.
    score = max(
        0,
        min(score, 100)
    )


    return score


def confidence_level(score):
    """
    Convert numerical confidence into an analyst-friendly level.
    """

    if score >= 85:
        return "VERY HIGH"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def build_confidence_summary(incident):
    """
    Return all confidence information used by HomeSOC.
    """

    score = calculate_confidence(
        incident
    )

    sources = sorted({
        event["source"]
        for event in incident.get(
            "events",
            []
        )
    })

    return {
        "confidence_score": score,

        "confidence_level": confidence_level(
            score
        ),

        "source_count": len(
            sources
        ),

        "sources": sources
    }