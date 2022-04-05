import React, { useState, useEffect } from 'react'
import api from '../api';
import PropTypes from 'prop-types'
import { Table } from 'react-bootstrap';
import { DimensionHead } from './DimensionHead'
import { ScoreBar } from '../Components/ScoreBar';
import TextField from '@material-ui/core/TextField';
import { CertificationPdf } from './CertificationPdf'


/**
 * Generate the RAI Certification document from the submission data.
 * @returns {React.Component}
 */
export default function Certification({ dimension, results, questions, subDimensions, submission }) {
  const [strengthsEditMode, setStrengthsEditMode] = useState(false);
  const [recommendationsEditMode, setRecommendationsEditMode] = useState(false);
  const [strengths, setStrengths] = useState('No recommendations yet.');
  const [improvements, setImprovements] = useState('No recommendations yet.');

  useEffect(() => {
    api
      .get(`submissions/submission/${submission?._id}`)
      .then((res) => {
        const submissionFromAPI = res.data.submission;
        if (submissionFromAPI?.recommendations) {
          const [currentRecommendations] = submissionFromAPI?.recommendations?.filter(r => r.dimensionId === dimension.dimensionID);
          setStrengths(currentRecommendations?.strengths?.length > 0 ? currentRecommendations?.strengths : 'No recommendations yet.');
          setImprovements(currentRecommendations?.improvements?.length > 0 ? currentRecommendations?.improvements : 'No recommendations yet.');
        }
      });
  }, []);

  const saveRecommendations = () => {
    const submissionRecommendations = submission?.recommendations ?? []
    function upsert(item) {
      const i = submissionRecommendations.findIndex(_item => _item.dimensionId === item.dimensionId);
      if (i > -1) submissionRecommendations[i] = item;
      else submissionRecommendations.push(item);
    }
    const updatedRecommendation = {
      dimensionId: dimension.dimensionID,
      strengths,
      improvements,
    };
    upsert(updatedRecommendation);
    if (submission) {
      api.post(`submissions/update/recommendations/${submission?._id}`, {
        recommendations: submissionRecommendations,
      }).then(res => {
        console.log('saved')
      }).catch(e => {
        console.log('error updating submission:', e)
      });
    }
    setStrengthsEditMode(false);
    setRecommendationsEditMode(false);
    console.log('saving this...', strengths, improvements)
  };
  const subDimensionsToDisplay = subDimensions.filter(d => d.dimensionID === dimension.dimensionID);
  return (
    <>
      <CertificationPdf />
      <DimensionHead dimension={dimension} questions={questions} results={results} />
      <div className="certification mt-3">
        <Table
          id={'certification-' + dimension}
          borderless
          responsive
          className="certification-table"
        >
          <thead>
            <tr role="row">
              <th
                role="columnheader"
                scope="col"
                className="certification-headers"
              >
                {dimension?.name} sub-dimension scores:
              </th>
              <th
                role="columnheader"
                scope="col"
                className="certification-headers"
              >
                Risk Scores
              </th>
              <th
                role="columnheader"
                scope="col"
                className="certification-headers"
              >
                Mitigation Scores
              </th>
            </tr>
          </thead>
          <tbody>
            {subDimensionsToDisplay.length > 0 && subDimensionsToDisplay.map((sd, index) => (
              <tr key={index}>
                <td>
                  <strong>{sd.name}</strong>
                  <p>{sd.description}</p>
                </td>
                <td><ScoreBar score={Math.floor(Math.random() * 101)} palette="risk" /></td>
                <td><ScoreBar score={Math.floor(Math.random() * 101)} palette="mitigation" /></td>
              </tr>
            ))}
          </tbody>
        </Table>
        <Table id={'recommendation-' + dimension}
          borderless
          responsive
          className="recommendation-table">
          <thead>
            <tr role="row">
              <th>Areas of strength:</th>
              <th>Opportunities for improvement:</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                {strengthsEditMode ? (
                  <TextField
                    id="strengths"
                    label="Areas of strength"
                    variant="outlined"
                    minRows={3}
                    multiline
                    value={strengths}
                    onChange={(e) => setStrengths(e.target.value === '' ? 'No recommendations yet.' : e.target.value)}
                    fullWidth
                    onBlur={() => saveRecommendations()}
                    autoFocus
                    style={{ minWidth: "25vw" }}
                  />
                ) : (<p style={strengths === 'No recommendations yet.' ? { color: "#8C8C8C" } : {}} onClick={() => setStrengthsEditMode(true)}>{strengths}</p>)}
              </td>
              <td>
                {recommendationsEditMode ? (
                  <TextField
                    id="improvements"
                    label="Opportunities for improvement"
                    variant="outlined"
                    minRows={3}
                    multiline
                    value={improvements}
                    onChange={(e) => setImprovements(e.target.value === '' ? 'No recommendations yet.' : e.target.value)}
                    fullWidth
                    onBlur={() => saveRecommendations()}
                    autoFocus
                    style={{ minWidth: "25vw" }}

                  />
                ) : (<p style={improvements === 'No recommendations yet.' ? { color: "#8C8C8C" } : {}} onClick={() => setRecommendationsEditMode(true)}>{improvements}</p>)}
              </td>
            </tr>
          </tbody>
        </Table>
      </div>
    </>
  );
}

Certification.propTypes = {
  dimension: PropTypes.object,
  results: PropTypes.object,
  questions: PropTypes.array,
}
